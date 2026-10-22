"""Step 4, part 3b (#88): call quality - per-minute jitter from the raw pings, the E-model's MOS,
and the Overview's Calls tile."""
import sqlite3
import time
import unittest
from unittest import mock

from hearth import calls, levels as lv, store
from hearth.config import inet_target
from tests.helpers import mem_db

INET = inet_target("1.1.1.1")


class MosTest(unittest.TestCase):
    def test_worked_examples(self):
        # a good line: 20 ms round trip, 2 ms jitter -> one way 10 + 20 + 4 = 34 ms, R = 92.35
        self.assertEqual(lv.mos(20, 2, 0), 4.39)
        # laggy: 300 ms, 30 ms jitter, 2% lost -> one way 230 ms, R = 93.2 - 11 - 5 = 77.2
        self.assertEqual(lv.mos(300, 30, 2), 3.91)
        # unusable: 40% lost
        self.assertEqual(lv.mos(20, 2, 40), 1.0)

    def test_more_of_anything_never_sounds_better(self):
        base = lv.mos(40, 5, 0.5)
        self.assertLess(lv.mos(80, 5, 0.5), base)
        self.assertLess(lv.mos(40, 15, 0.5), base)
        self.assertLess(lv.mos(40, 5, 3), base)

    def test_levels(self):
        self.assertEqual(lv.call_quality(None)["level"], lv.UNKNOWN)
        self.assertEqual(lv.call_quality({"rtt_ms": None, "loss_pct": 100})["mos"], 1.0)   # sent, nothing back
        good = lv.call_quality({"rtt_ms": 20, "jitter_ms": 2, "loss_pct": 0})
        self.assertEqual((good["level"], good["mos"]), (lv.OK, 4.39))
        self.assertIn("good for calls", good["why"])
        self.assertEqual(lv.call_quality({"rtt_ms": 300, "jitter_ms": 30, "loss_pct": 2})["level"], lv.WARN)
        self.assertEqual(lv.call_quality({"rtt_ms": 400, "jitter_ms": 50, "loss_pct": 8})["level"], lv.BAD)


class JitterRollupTest(unittest.TestCase):
    def test_mean_difference_between_consecutive_replies_in_the_minute(self):
        c = mem_db()
        self.addCleanup(c.close)
        m = 1_792_000_020 // 60 * 60
        rtts = [10.0, 14.0, None, 11.0, 19.0]   # differences 4, (lost breaks it), 8 -> 6
        c.executemany("INSERT INTO pings VALUES (?, ?, ?)", [(m + i, INET, r) for i, r in enumerate(rtts)])
        c.execute("INSERT INTO pings VALUES (?, ?, ?)", (m + 60, INET, 50.0))   # next minute: not compared across
        store.rollup(c, m + 120)
        rows = dict(c.execute("SELECT ts, jitter FROM pings_1m ORDER BY ts").fetchall())
        self.assertEqual(rows[m], 6.0)
        self.assertIsNone(rows[m + 60])                                      # one reply: no difference
        self.assertEqual(c.execute("SELECT n, lost FROM pings_1m WHERE ts = ?", (m,)).fetchone(), (5, 1))

    def test_an_existing_install_gains_the_column(self):
        c = sqlite3.connect(":memory:")
        self.addCleanup(c.close)
        c.execute("CREATE TABLE pings_1m (ts INTEGER NOT NULL, target TEXT NOT NULL, n INTEGER NOT NULL, "
                  "lost INTEGER NOT NULL, avg REAL, max REAL, PRIMARY KEY (target, ts))")
        c.execute("INSERT INTO pings_1m VALUES (60, 't', 1, 0, 5.0, 5.0)")
        class Kept:   # init_db closes its connection: keep this one open to look at afterwards
            def __getattr__(self, name):
                return getattr(c, name)

            def close(self):
                pass
        with mock.patch.object(store, "db", return_value=Kept()):
            store.init_db()
        cols = [r[1] for r in c.execute("PRAGMA table_info(pings_1m)")]
        self.assertIn("jitter", cols)
        self.assertEqual(c.execute("SELECT jitter FROM pings_1m").fetchone(), (None,))   # old rows: unknown


class TileTest(unittest.TestCase):
    def test_the_last_five_minutes_rated_and_a_series(self):
        c = mem_db()
        self.addCleanup(c.close)
        now = time.time()
        end = int(now // 60 * 60)
        rows = [(end - 60 * i, INET, 60, 0, 20.0, 30.0, 2.0) for i in range(1, 11)]
        c.executemany("INSERT INTO pings_1m (ts, target, n, lost, avg, max, jitter) VALUES (?,?,?,?,?,?,?)", rows)
        k = calls.calls_kpi(c, now)
        self.assertEqual((k["level"], k["mos"], k["rtt_ms"], k["jitter_ms"], k["loss_pct"]), (lv.OK, 4.39, 20.0, 2.0, 0))
        self.assertEqual(len(k["series"]), 10)
        self.assertEqual(k["series"][-1], [end - 60, 4.39])

    def test_an_outage_is_poor_not_hidden(self):
        # #95: four of the last five minutes with every ping lost read "good, 0% lost" when those
        # minutes were dropped; summed, they're 80% lost - poor - and each is MOS 1 on the series
        c = mem_db()
        self.addCleanup(c.close)
        now = time.time()
        end = int(now // 60 * 60)
        rows = [(end - 60, INET, 60, 0, 20.0, 30.0, 2.0)] + [(end - 60 * i, INET, 60, 60, None, None, None) for i in range(2, 6)]
        c.executemany("INSERT INTO pings_1m (ts, target, n, lost, avg, max, jitter) VALUES (?,?,?,?,?,?,?)", rows)
        k = calls.calls_kpi(c, now)
        self.assertEqual((k["level"], k["loss_pct"]), (lv.BAD, 80.0))
        self.assertEqual([p[1] for p in k["series"]], [1.0, 1.0, 1.0, 1.0, 4.39])

    def test_a_full_outage_is_a_failed_call_not_unmeasured(self):
        c = mem_db()
        self.addCleanup(c.close)
        now = time.time()
        end = int(now // 60 * 60)
        c.executemany("INSERT INTO pings_1m (ts, target, n, lost, avg, max, jitter) VALUES (?,?,?,?,?,?,?)",
                      [(end - 60 * i, INET, 60, 60, None, None, None) for i in range(1, 6)])
        k = calls.calls_kpi(c, now)
        self.assertEqual((k["level"], k["mos"], k["loss_pct"]), (lv.BAD, 1.0, 100.0))
        self.assertIn("a call would fail", k["why"])

    def test_minutes_are_weighted_by_what_was_sent(self):
        # #95: a minute with 6 pings doesn't count as much as one with 60
        c = mem_db()
        self.addCleanup(c.close)
        now = time.time()
        end = int(now // 60 * 60)
        c.executemany("INSERT INTO pings_1m (ts, target, n, lost, avg, max, jitter) VALUES (?,?,?,?,?,?,?)",
                      [(end - 60, INET, 60, 0, 20.0, 20.0, 2.0), (end - 120, INET, 6, 0, 200.0, 200.0, 2.0)])
        k = calls.calls_kpi(c, now)
        self.assertEqual(k["rtt_ms"], round((60 * 20 + 6 * 200) / 66, 1))

    def test_nothing_measured(self):
        c = mem_db()
        self.addCleanup(c.close)
        k = calls.calls_kpi(c, time.time())
        self.assertEqual((k["level"], k["mos"], k["series"]), (lv.UNKNOWN, None, []))



class QualitySeriesTest(unittest.TestCase):
    """#101: the History tab's call rating over the range (and DNS from dns_health)."""

    def test_buckets_sum_their_minutes_and_an_outage_counts(self):
        c = mem_db()
        self.addCleanup(c.close)
        now = time.time()
        end = int(now // 60 * 60)
        rows = [(end - 60 * i, INET, 60, 0, 20.0, 30.0, 2.0) for i in range(1, 30)]
        rows += [(end - 60 * i, INET, 60, 60, None, None, None) for i in range(30, 40)]     # ten dead minutes
        c.executemany("INSERT INTO pings_1m (ts, target, n, lost, avg, max, jitter) VALUES (?,?,?,?,?,?,?)", rows)
        q = calls.quality_view(c, 60)
        self.assertEqual(q["bucket_s"], 60)
        values = [m for _, m in q["mos"]]
        self.assertIn(1.0, values)                                  # the outage minutes rate as a failed call
        self.assertEqual(values[-1], 4.39)
        self.assertEqual(q["dns"], [])
        q = calls.quality_view(c, 1440)                             # 4-minute buckets over a day
        self.assertEqual(q["bucket_s"], 240)


if __name__ == "__main__":
    unittest.main()
