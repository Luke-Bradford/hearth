"""Part 2 of step 2 (#64): hourly summaries of the detail tables, kept 400 days."""
import time
import unittest
from unittest import mock

from hearth import analysis, config, store
from tests.helpers import mem_db

H0 = int(time.time()) // 3600 * 3600 - 10 * 3600     # an hour boundary ten hours ago


def rows(c, table):
    return c.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()


class RollupTest(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)

    def test_router_hour_averages_maxima_and_a_restart(self):
        # hour 0: steady (up for days); hour 1: rebooted 20 minutes in
        self.c.executemany("INSERT INTO router_stats VALUES (?,?,?,?,?)", [
            (H0 + 60, 50.0, 900000, 0.5, 40.0), (H0 + 1800, 54.0, 901740, 1.5, 44.0),
            (H0 + 3600 + 600, 52.0, 902340, 1.0, 42.0),
            (H0 + 3600 + 1500, 48.0, 300, 0.2, 30.0)])                  # uptime 300 s: booted at +1200
        store.rollup_hourly(self.c, H0 + 3 * 3600)
        r = rows(self.c, "router_stats_1h")
        self.assertEqual(r[0], (H0, 52.0, 54.0, 1.0, 42.0, 0))
        self.assertEqual(r[1][0], H0 + 3600)
        self.assertEqual(r[1][-1], 1)                                     # restarted in that hour

    def test_backhaul_per_unit_and_band(self):
        self.c.executemany("INSERT INTO mesh_backhaul VALUES (?,?,?,?,?,?)", [
            (H0 + 10, "aa", "band5", -55, 1000, 900), (H0 + 20, "aa", "band5", -61, 800, 700),
            (H0 + 30, "aa", "band6", -60, 2000, 1900), (H0 + 40, "bb", "band5", -70, None, None)])
        store.rollup_hourly(self.c, H0 + 2 * 3600)
        self.assertEqual(rows(self.c, "mesh_backhaul_1h"), [
            (H0, "aa", "band5", -58.0, -61, 900.0, 800.0, 2), (H0, "aa", "band6", -60.0, -60, 2000.0, 1900.0, 1),
            (H0, "bb", "band5", -70.0, -70, None, None, 1)])

    def test_traffic_and_host(self):
        self.c.executemany("INSERT INTO traffic VALUES (?,?,?)", [(H0 + 1, 10.0, 1.0), (H0 + 2, 30.0, 3.0)])
        self.c.executemany("INSERT INTO host_stats VALUES (?,?,?,?,?,?,?,?,?,?)", [
            (H0 + 60, 10.0, 8000, 16000, 100, 200, 5, 6, 1000, 50000),
            (H0 + 120, 30.0, 6000, 16000, 120, 200, 7, 4, 1200, 50060)])
        store.rollup_hourly(self.c, H0 + 2 * 3600)
        self.assertEqual(rows(self.c, "traffic_1h"), [(H0, 20.0, 2.0, 30.0, 3.0)])
        self.assertEqual(rows(self.c, "host_stats_1h"), [(H0, 20.0, 6000, 16000, 120, 200, 7, 6, 1200, 50000)])

    def test_catch_up_after_a_gap_resume_and_rerun(self):
        for h in (0, 1, 2, 5):                                            # Hearth stopped for hours 3-4
            self.c.execute("INSERT INTO traffic VALUES (?,?,?)", (H0 + h * 3600 + 5, float(h), 0.0))
        store.rollup_hourly(self.c, H0 + 2 * 3600 + 200)                 # hours 0 and 1 have closed
        self.assertEqual([r[0] for r in rows(self.c, "traffic_1h")], [H0, H0 + 3600])
        store.rollup_hourly(self.c, H0 + 7 * 3600)                       # later: the rest, from hour 2 on
        self.assertEqual([r[0] for r in rows(self.c, "traffic_1h")], [H0 + h * 3600 for h in (0, 1, 2, 5)])
        before = rows(self.c, "traffic_1h")
        store.rollup_hourly(self.c, H0 + 7 * 3600)
        self.assertEqual(rows(self.c, "traffic_1h"), before)             # a re-run changes nothing

    def test_a_partial_first_hour_isnt_written_as_whole(self):
        self.c.executemany("INSERT INTO traffic VALUES (?,?,?)", [(H0 + 1800, 1.0, 1.0), (H0 + 3600 + 10, 2.0, 2.0)])
        store.rollup_hourly(self.c, H0 + 3 * 3600)
        self.assertEqual([r[0] for r in rows(self.c, "traffic_1h")], [H0 + 3600])

    def test_an_hour_closes_only_after_it_has_ended(self):
        self.c.execute("INSERT INTO traffic VALUES (?,?,?)", (H0 + 10, 1.0, 1.0))
        store.rollup_hourly(self.c, H0 + 3600 + 60)                      # 1 minute after: not yet
        self.assertEqual(rows(self.c, "traffic_1h"), [])
        store.rollup_hourly(self.c, H0 + 3600 + 180)
        self.assertEqual(len(rows(self.c, "traffic_1h")), 1)

    def test_hourly_tables_kept_for_the_rollup_period(self):
        now = time.time()
        old, keep = int(now - (store.ROLLUP_DAYS + 1) * 86400) // 3600 * 3600, int(now - 30 * 86400) // 3600 * 3600
        for t in (old, keep):
            self.c.execute("INSERT INTO traffic_1h VALUES (?,1,1,1,1)", (t,))
            self.c.execute("INSERT INTO router_stats_1h VALUES (?,1,1,1,1,0)", (t,))
        store.prune(self.c, now)
        for table in ("traffic_1h", "router_stats_1h"):
            self.assertEqual([r[0] for r in rows(self.c, table)], [keep], table)

    def test_events_kept_90_days_by_default(self):
        self.assertEqual(config.DEFAULTS["retention_days"], 90)


class LongRangeReadersTest(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)

    def test_host_series_from_hourly_rows_past_the_detail_retention(self):
        now = time.time()
        self.c.execute("INSERT INTO host_stats VALUES (?,?,?,?,?,?,?,?,?,?)",
                       (now - 30, 5.0, 8000, 16000, 100, 200, 5, 6, 1000, 50000))   # a current reading
        old = int(now - 20 * 86400) // 3600 * 3600                         # long gone from host_stats
        self.c.execute("INSERT INTO host_stats_1h VALUES (?,?,?,?,?,?,?,?,?,?)",
                       (old, 42.0, 4000, 16000, 150, 200, 9, 9, 2000, 10))
        short = analysis.host_view(self.c, 60)["series"]["points"]
        long_ = analysis.host_view(self.c, 30 * 1440)["series"]["points"]
        self.assertFalse(any(p[1] == 42.0 for p in short))
        self.assertTrue(any(p[1] == 42.0 for p in long_))
        self.assertEqual(analysis.host_view(self.c, 30 * 1440)["series"]["bucket_s"] % 3600, 0)

    def test_long_range_switch_point(self):
        self.assertFalse(analysis.long_range(int(store.DETAIL_DAYS * 1440)))
        self.assertTrue(analysis.long_range(int(store.DETAIL_DAYS * 1440) + 1))

    def test_mesh_signal_history_from_hourly_rows(self):
        now = time.time()
        old = int(now - 20 * 86400) // 3600 * 3600
        self.c.execute("INSERT INTO mesh_backhaul_1h VALUES (?,?,?,?,?,?,?,?)", (old, "aa", "band5", -63.0, -70, 1, 1, 4))
        store.set_state(self.c, "mesh", {"ts": now, "nodes": [{"mac": "aa", "name": "Office", "ip": "192.168.1.2",
                                                               "role": "satellite", "online": True}], "clients": []})
        with mock.patch.object(analysis, "_my_ip", return_value="192.168.1.60"), \
                mock.patch.object(analysis, "_gateway_ip", return_value="192.168.1.254"):
            v = analysis.mesh_view(self.c, 30 * 1440)
        b = v["history"]["bucket_s"]
        self.assertEqual(b % 3600, 0)
        self.assertEqual(v["history"]["series"].get("aa|band5"), [[old // b * b, -63.0]])


if __name__ == "__main__":
    unittest.main()
