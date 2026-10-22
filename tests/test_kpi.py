import time
import unittest
from unittest import mock

from hearth import analysis, store
from tests.helpers import mem_db


class RouterHealthTest(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)
        self.now = time.time()

    def add(self, ago, temp, uptime=3600):
        store.add_router_stats(self.c, self.now - ago, {"temp_c": temp, "uptime_s": uptime, "load1": 0.1,
                                                         "mem_used_pct": 33.0})

    def test_latest_reading_level_and_day_of_temperatures(self):
        self.add(2 * 86400, 99.0)  # older than a day: not in the series
        self.add(1200, 60.0)
        self.add(30, 80.0, uptime=8000)
        h = analysis.router_health(self.c, self.now)
        self.assertTrue(h["available"])
        self.assertEqual((h["temp_c"], h["uptime_s"], h["level"]), (80.0, 8000, "warn"))
        self.assertEqual([t for _, t in h["series"]], [60.0, 80.0])

    def test_levels_follow_the_thresholds(self):
        from hearth import levels
        for temp, level in ((74.9, "ok"), (75, "warn"), (85, "bad"), (None, "unknown")):
            self.assertEqual(levels.temp_level(temp, 75, 85)["level"], level, temp)

    def test_bad_limits_fall_back_to_both_defaults(self):
        defaults = (75.0, 85.0)
        for warn, bad in (("x", 85), (float("nan"), 85), (75, float("inf")), (90, 80), (80, 80), (None, 85)):
            with mock.patch.dict(analysis.CFG, router_temp_warn_c=warn, router_temp_bad_c=bad):
                self.assertEqual(analysis.router_temp_limits(), defaults, (warn, bad))
        with mock.patch.dict(analysis.CFG, router_temp_warn_c=60, router_temp_bad_c="70"):
            self.assertEqual(analysis.router_temp_limits(), (60.0, 70.0))

    def test_old_or_missing_reading_is_unavailable(self):
        self.assertFalse(analysis.router_health(self.c, self.now)["available"])
        self.add(analysis.ROUTER_STATS_MAX_AGE_S + 60, 50.0)
        h = analysis.router_health(self.c, self.now)
        self.assertFalse(h["available"])
        self.assertEqual(h["level"], "unknown")

    def test_status_reports_temperature_for_home_assistant(self):
        self.add(30, 52.0, uptime=8265)
        st = analysis.status(self.c)
        self.assertEqual((st["router_temp_c"], st["router_uptime_s"]), (52.0, 8265))


class InternetKpiTest(unittest.TestCase):
    def st(self, loss, p50, p95, up=True):
        return {"loss_pct_5m": loss, "internet_ms": p50, "internet_p95_ms": p95, "internet_up": up, "incidents_1h": 2,
                "episodes_1h": 1, "spikes_1h": 41, "spikes_usual_per_hour": 35}

    def test_grades_loss_and_slowest_pings_against_typical(self):
        self.assertEqual(analysis.internet_kpi(self.st(0.0, 16, 30))["level"], "ok")
        self.assertEqual(analysis.internet_kpi(self.st(0.8, 16, 101))["level"], "warn")  # +85 ms
        self.assertEqual(analysis.internet_kpi(self.st(1.5, 16, 20))["level"], "warn")
        self.assertEqual(analysis.internet_kpi(self.st(6.0, 16, 20))["level"], "bad")
        self.assertEqual(analysis.internet_kpi(self.st(0.0, 16, 140))["level"], "bad")
        self.assertEqual(analysis.internet_kpi(self.st(100.0, None, None, up=False))["level"], "bad")
        self.assertEqual(analysis.internet_kpi(self.st(None, None, None, up=False))["level"], "unknown")  # nothing measured

    def test_tiles_have_a_reason(self):
        k = analysis.internet_kpi(self.st(0.0, 16, 30))
        self.assertIn("lost", k["why"])

    def test_carries_the_figures(self):
        k = analysis.internet_kpi(self.st(0.8, 16, 101))
        self.assertEqual((k["loss_pct"], k["p50_ms"], k["p95_ms"], k["incidents_1h"]), (0.8, 16, 101, 2))

    def test_episode_and_spike_figures_pass_through(self):
        k = analysis.internet_kpi(self.st(0.0, 16, 30))
        self.assertEqual((k["episodes_1h"], k["spikes_1h"], k["spikes_usual_per_hour"]), (1, 41, 35))


class StatusEpisodesTest(unittest.TestCase):
    def test_status_has_episode_fields_and_keeps_incidents(self):
        c = mem_db()
        self.addCleanup(c.close)
        analysis.clear_cache()
        st = analysis.status(c)
        for k in ("episodes_1h", "spikes_1h", "spikes_usual_per_hour", "last_episode", "incidents_1h"):
            self.assertIn(k, st)

    def test_status_carries_what_the_header_and_banner_need_on_every_tab(self):
        # step 3: the dashboard's header reads /api/status on every tab, not the incidents list
        c = mem_db()
        self.addCleanup(c.close)
        analysis.clear_cache()
        st = analysis.status(c)
        self.assertIn("episodes_level_1h", st)
        self.assertIn("episodes_breakdown_1h", st)
        self.assertIs(st["mesh_pending"], False)
        with mock.patch.object(analysis.mesh, "pending_cert", return_value={"host": "192.168.1.231"}):
            analysis.clear_cache()
            self.assertIs(analysis.status(c)["mesh_pending"], True)


def node(name, role="satellite", online=True, backhaul="wireless", rssi=None, rate=None):
    """A mesh node as mesh_view returns it, with the level it gives such a node."""
    from hearth import levels
    n = {"name": name, "mac": name, "role": role, "online": online, "backhaul": backhaul,
         "rssi": rssi or {}, "rate_rx": rate or {}}
    if not online:
        n.update(levels.result(levels.BAD, "not connected to the mesh"))
    elif backhaul == "wired" or role == "main":
        n.update(levels.result(levels.OK, "wired"))
    else:
        n.update(levels.signal_level(max(n["rssi"].values()) if n["rssi"] else None))
    return n


class MeshKpiTest(unittest.TestCase):
    def test_weakest_satellite_by_its_best_band(self):
        mv = {"available": True, "nodes": [
            node("Bedroom", role="main", backhaul=None),
            node("Office", rssi={"band5": -57, "band6": -60}, rate={"band5": 1153}),
            node("Living Room", rssi={"band5": -70, "band6": -78}, rate={"band5": 600})]}
        k = analysis.mesh_kpi(mv)
        self.assertEqual((k["name"], k["band"], k["rssi"], k["level"], k["satellites"]),
                         ("Living Room", "band5", -70, "warn", 2))

    def test_offline_beats_weak_and_wired_is_good(self):
        mv = {"available": True, "nodes": [node("A", rssi={"band5": -80}), node("B", online=False),
                                           node("C", backhaul="wired")]}
        self.assertEqual((analysis.mesh_kpi(mv)["name"], analysis.mesh_kpi(mv)["level"]), ("B", "bad"))
        k = analysis.mesh_kpi({"available": True, "nodes": [node("C", backhaul="wired")]})
        self.assertEqual((k["backhaul"], k["level"]), ("wired", "ok"))

    def test_no_satellites_or_no_mesh(self):
        self.assertEqual(analysis.mesh_kpi({"available": True, "nodes": [node("M", role="main")]})["satellites"], 0)
        self.assertFalse(analysis.mesh_kpi({"available": False})["available"])


class WifiKpiTest(unittest.TestCase):
    def test_counts_wireless_devices_and_names_poor_ones(self):
        mv = {"available": True, "devices": [
            {"name": "Mac", "link": "band6", "quality": "poor", "quality_why": "114 ms"},
            {"name": "Phone", "link": "band5", "quality": "sleepy"},
            {"name": "Laptop", "link": "band5", "quality": "fair"},
            {"name": "PC", "link": "wired"}]}
        k = analysis.wifi_kpi(mv)
        self.assertEqual((k["total"], k["fair"], k["level"]), (3, 1, "warn"))
        self.assertEqual(k["poor"], [{"name": "Mac", "why": "114 ms"}])
        self.assertEqual(analysis.wifi_kpi({"available": True, "devices": []})["level"], "unknown")  # nothing to judge
        nameless = analysis.wifi_kpi({"available": True, "devices": [{"mac": "aa:bb", "link": "band5", "quality": "poor"}]})
        self.assertEqual(nameless["poor"][0]["name"], "aa:bb")


class KpiViewTest(unittest.TestCase):
    def test_runs_with_nothing_measured_yet(self):
        c = mem_db()
        self.addCleanup(c.close)
        analysis.clear_cache()
        k = analysis.kpi_view(c, 60)
        analysis.clear_cache()
        self.assertEqual(set(k), {"now", "router", "internet", "today", "mesh", "wifi", "verdict", "calls"})
        self.assertEqual(k["calls"]["level"], "unknown")                 # nothing measured: not "good"
        self.assertEqual(k["verdict"], {"level": "unknown", "text": "Hearth is still measuring."})
        self.assertFalse(k["router"]["available"])
        self.assertIsNone(k["today"])


class IncidentsEpisodesTest(unittest.TestCase):
    def test_outage_and_blip_in_the_window(self):
        c = mem_db()
        self.addCleanup(c.close)
        now = time.time()
        t0 = int(now) - 600
        rows = []
        for s in range(t0, t0 + 300):
            dark = t0 + 100 <= s < t0 + 115                       # a 15 s outage
            for tgt in ("inet:1.1.1.1", "inet:8.8.8.8"):
                rows.append((s + 0.2, tgt, None if dark else 18.0))
            rows.append((s + 0.1, "gateway", 2.0))
        rows.append((t0 + 200.2, "inet:1.1.1.1", 400.0))          # one slow reply: a blip
        c.executemany("INSERT INTO pings VALUES (?,?,?)", rows)
        analysis.clear_cache()
        out = analysis.incidents(c, 30)
        self.assertEqual([e["kind"] for e in out["episodes"]], ["outage"])
        self.assertEqual(out["episode_total"], 1)
        self.assertEqual(out["spikes_total"], len(out["momentary"]))  # the list matches its count
        self.assertTrue(any("1.1.1.1" in str(b.get("targets")) for b in out["blips"]))  # the lone slow reply
        self.assertEqual(out["episode_breakdown"], "1 outage")
        self.assertEqual(out["episode_level"], "bad")
        self.assertIn("total", out)  # the old fields stay for one release

    def test_sweeps_traffic_and_events_matched_by_time(self):
        # found by binary search, not a scan per incident: same answers at the edges
        c = mem_db()
        self.addCleanup(c.close)
        t0 = int(time.time()) - 600
        rows = []
        for s in range(t0, t0 + 300):
            dark = t0 + 100 <= s < t0 + 115
            for tgt in ("inet:1.1.1.1", "inet:8.8.8.8"):
                rows.append((s + 0.2, tgt, None if dark else 18.0))
            rows.append((s + 0.1, "gateway", 2.0))
        c.executemany("INSERT INTO pings VALUES (?,?,?)", rows)
        # a long sweep, then a short one starting later but ending sooner: the long one still covers it
        c.executemany("INSERT INTO sweeps VALUES (?,?)", [(t0 + 50, t0 + 150), (t0 + 60, t0 + 70)])
        c.executemany("INSERT INTO traffic VALUES (?,?,?)",
                      [(t0 + 101.0, 7.5, 1.5), (t0 + 140.0, 99.0, 99.0)])     # inside, and well after
        c.executemany("INSERT INTO events VALUES (?,?,?)",
                      [(t0 + 20.0, "wifi_new", "near enough"), (t0 + 2.0, "wifi_new", "too early")])
        res, _ = analysis.cluster_window(c, t0, t0 + 300)
        dark = next(r for r in res if r["start"] <= t0 + 105 <= r["end"])
        self.assertTrue(dark["during_sweep"])
        self.assertIn("near enough", dark["context"])
        self.assertNotIn("too early", dark["context"])
        self.assertIn("peak 7.5 Mb/s in, 1.5 Mb/s out", " ".join(dark["context"]))


class SpikeHoursTest(unittest.TestCase):
    def _db(self, hours, gap=None):
        """`hours` of steady pings ending at `now` (10 minutes past an hour). gap: (start, end)
        seconds with no pings, e.g. Hearth down."""
        c = mem_db()
        self.addCleanup(c.close)
        now = (int(time.time()) // 3600) * 3600 + 600
        rows = []
        for s in range(now - hours * 3600, now):
            if gap and gap[0] <= s < gap[1]:
                continue
            rows += [(s + 0.2, "inet:1.1.1.1", 18.0), (s + 0.2, "inet:8.8.8.8", 18.0)]
        c.executemany("INSERT INTO pings VALUES (?,?,?)", rows)
        return c, now

    def fill_all(self, c, now):
        while analysis.fill_spike_hours(c, now):
            pass

    def test_fresh_install_has_no_usual(self):
        c, now = self._db(3)
        self.fill_all(c, now)
        self.assertIsNone(analysis.spike_usual(c, now))

    def test_enough_monitored_hours_give_a_usual(self):
        c, now = self._db(9)
        self.fill_all(c, now)
        self.assertEqual(analysis.spike_usual(c, now), 0)

    def test_requests_never_compute_hours(self):
        c, now = self._db(9)
        self.assertIsNone(analysis.spike_usual(c, now))          # nothing filled yet: read-only
        self.assertEqual(c.execute("SELECT COUNT(*) FROM spike_hours").fetchone()[0], 0)

    def test_at_most_max_hours_per_call(self):
        c, now = self._db(9)
        self.assertEqual(analysis.fill_spike_hours(c, now, max_hours=4), 4)

    def test_hour_in_progress_or_its_edge_is_not_cached(self):
        c, now = self._db(9)
        self.fill_all(c, now)
        newest = c.execute("SELECT MAX(hour) FROM spike_hours").fetchone()[0]
        self.assertLessEqual(newest + 3600 + analysis.EPISODE_EDGE_S, now)

    def test_partly_monitored_hour_is_skipped(self):
        hour = (int(time.time()) // 3600) * 3600 - 3 * 3600
        c, now = self._db(9, gap=(hour + 600, hour + 1200))     # 10 min of Hearth being down
        self.fill_all(c, now)
        hours = {h for (h,) in c.execute("SELECT hour FROM spike_hours")}
        self.assertNotIn(hour, hours)
        self.assertIn(hour - 3600, hours)

    def test_episode_across_the_hour_marks_both(self):
        c, now = self._db(9)
        hour = (now // 3600) * 3600 - 3 * 3600                  # an hour boundary 3 h ago
        c.execute("DELETE FROM pings WHERE ts >= ? AND ts < ?", (hour - 20, hour + 20))
        rows = []
        for s in range(hour - 20, hour + 20):                   # 40 s dark across the boundary
            rows += [(s + 0.2, "inet:1.1.1.1", None), (s + 0.2, "inet:8.8.8.8", None), (s + 0.1, "gateway", 2.0)]
        c.executemany("INSERT INTO pings VALUES (?,?,?)", rows)
        self.fill_all(c, now)
        bad = dict(c.execute("SELECT hour, bad FROM spike_hours"))
        self.assertEqual((bad[hour - 3600], bad[hour]), (1, 1))

    def test_cluster_near_the_window_edge_makes_the_hour_uncertain(self):
        # a slow reply 2 minutes before the hour: within one grouping gap of the window's start,
        # so an episode could reach beyond it - the hour is left out of "usual"
        c, now = self._db(9)
        hour = (now // 3600) * 3600 - 3 * 3600
        t = hour - analysis.EPISODE_EDGE_S + 5
        c.execute("DELETE FROM pings WHERE ts >= ? AND ts < ?", (t, t + 12))
        c.executemany("INSERT INTO pings VALUES (?,?,?)",
                      [(s + 0.2, tgt, 900.0) for s in range(t, t + 12) for tgt in ("inet:1.1.1.1", "inet:8.8.8.8")])
        while analysis.fill_spike_hours(c, now):
            pass
        self.assertEqual(dict(c.execute("SELECT hour, bad FROM spike_hours"))[hour], 1)

    def test_a_failing_hour_is_skipped_not_blocking(self):
        from unittest import mock
        c, now = self._db(9)
        real = analysis.episode_window
        failing = (now // 3600) * 3600 - 2 * 3600

        def flaky(conn, lo, hi):
            if lo <= failing < hi and hi - lo < 2 * 3600 and lo > failing - 3600:
                raise KeyError("odd data")
            return real(conn, lo, hi)
        skip = set()
        with mock.patch.object(analysis, "episode_window", side_effect=flaky):
            for _ in range(20):
                try:
                    if not analysis.fill_spike_hours(c, now, skip=skip):
                        break
                except KeyError:
                    pass
        self.assertIn(failing, skip)
        self.assertGreaterEqual(c.execute("SELECT COUNT(*) FROM spike_hours").fetchone()[0], 6)

    def test_unmonitored_hours_are_remembered(self):
        hour = (int(time.time()) // 3600) * 3600 - 3 * 3600
        c, now = self._db(9, gap=(hour + 600, hour + 1200))
        skip = set()
        while analysis.fill_spike_hours(c, now, skip=skip):
            pass
        self.assertIn(hour, skip)

    def test_loop_survives_any_error(self):
        from unittest import mock
        from hearth import collectors
        import threading
        stop = threading.Event()
        calls = []

        def boom(*a, **k):
            calls.append(1)
            if len(calls) >= 2:
                stop.set()
            raise KeyError("odd data")
        with mock.patch.object(collectors.analysis, "fill_spike_hours", side_effect=boom), \
                mock.patch.object(collectors, "SPIKE_HOURS_INTERVAL_S", 0), \
                mock.patch.object(collectors.store, "db", return_value=mock.Mock()), \
                mock.patch.object(stop, "wait", side_effect=lambda t=None: stop.is_set()):
            collectors.spike_hours_loop(stop)
        self.assertEqual(len(calls), 2)  # it carried on after the first error


class WholeWindowOutageTest(unittest.TestCase):
    """An outage longer than the window: no internet target answers at all inside it."""

    def dark_db(self, router=2.0, targets=("inet:1.1.1.1", "inet:8.8.8.8")):
        c = mem_db()
        self.addCleanup(c.close)
        now = int(time.time())
        rows = []
        for s in range(now - 3600, now):
            rows += [(s + 0.2, t, None) for t in targets]
            rows.append((s + 0.1, "gateway", router))
        c.executemany("INSERT INTO pings VALUES (?,?,?)", rows)
        analysis.clear_cache()
        return c

    def test_fully_dark_window_is_an_outage(self):
        out = analysis.incidents(self.dark_db(), 30)
        self.assertEqual([e["kind"] for e in out["episodes"]], ["outage"])

    def test_fully_dark_with_the_router_silent_is_a_home_network_outage(self):
        out = analysis.incidents(self.dark_db(router=None), 30)
        self.assertEqual([e["kind"] for e in out["episodes"]], ["home_down"])

    def test_single_configured_target_dark_is_an_outage(self):
        with mock.patch.dict(analysis.CFG, {"internet_targets": ["1.1.1.1"]}):
            out = analysis.incidents(self.dark_db(targets=("inet:1.1.1.1",)), 30)
        self.assertEqual([(e["kind"], e["level"]) for e in out["episodes"]], [("outage", "bad")])


class SlowerPingIntervalTest(unittest.TestCase):
    def test_two_second_interval_still_finds_an_outage_and_monitored_hours(self):
        c = mem_db()
        self.addCleanup(c.close)
        now = int(time.time())
        rows = []
        for s in range(now - 600, now, 2):                       # pinged every 2 s
            dark = now - 300 <= s < now - 260                    # 40 s outage
            rows += [(s + 0.2, t, None if dark else 18.0) for t in ("inet:1.1.1.1", "inet:8.8.8.8")]
            rows.append((s + 0.1, "gateway", 2.0))
        c.executemany("INSERT INTO pings VALUES (?,?,?)", rows)
        analysis.clear_cache()
        with mock.patch.dict(analysis.CFG, {"core_interval_s": 2.0}):
            out = analysis.incidents(c, 15)
            self.assertEqual([e["kind"] for e in out["episodes"]], ["outage"])
            hour = (now - 600) // 3600 * 3600
            full = [(s + 0.2, t, 18.0) for s in range(hour - 7200, hour - 3600, 2) for t in ("inet:1.1.1.1",)]
            c.executemany("INSERT INTO pings VALUES (?,?,?)", full)
            self.assertTrue(analysis._monitored(c, hour - 7200))


class InternetMeasuredTest(unittest.TestCase):
    def test_no_recent_pings_is_not_measured(self):
        c = mem_db()
        self.addCleanup(c.close)
        now = time.time()
        c.executemany("INSERT INTO pings VALUES (?,?,?)",
                      [(now - 200 + i, "inet:1.1.1.1", 18.0) for i in range(100)])   # stopped 100 s ago
        analysis.clear_cache()
        st = analysis.status(c)
        self.assertEqual((st["internet_up"], st["internet_measured"]), (False, False))
        tile = analysis.internet_kpi(st)
        self.assertEqual((tile["level"], tile["up"], tile["measured"]), ("unknown", None, False))  # never "down"


class LevelsReviewTest(unittest.TestCase):
    """From the whole-branch review of #38 part 2."""

    def test_wifi_tile_judges_only_measured_devices(self):
        unmeasured = {"available": True, "devices": [{"name": "Phone", "link": "band5", "level": "unknown"}]}
        self.assertEqual(analysis.wifi_kpi(unmeasured)["level"], "unknown")
        judged = {"available": True, "devices": [{"name": "Laptop", "link": "band5", "level": "ok", "quality": "good"}]}
        self.assertEqual(analysis.wifi_kpi(judged)["level"], "ok")

    def test_unknown_internet_with_nothing_else_wrong_is_unknown(self):
        v = analysis.verdict_from({"level": "unknown", "up": None}, 0, {"level": "ok"}, {"level": "ok"},
                                  {"level": "ok", "poor": []})
        self.assertEqual(v["level"], "unknown")   # not a green dot next to "hasn't been measured"

    def test_dozing_member_doesnt_colour_its_group(self):
        stats = {"a": {"samples": 10, "p50": 5, "p95": 8, "loss_pct": 0},
                 "phone": {"samples": 10, "p50": None, "p95": None, "loss_pct": 100.0}}
        self.assertEqual(analysis.group_level(["a", "phone"], stats, {}, skip={"phone"})["level"], "ok")
        self.assertEqual(analysis.group_level(["a", "phone"], stats, {})["level"], "bad")

    def test_host_process_cells_get_levels(self):
        c = mem_db()
        self.addCleanup(c.close)
        now = time.time()
        c.execute("INSERT INTO host_stats VALUES (?,?,?,?,?,?,?,?,?,?)",
                  (now - 30, 5.0, 70 * 2**30, 128 * 2**30, 60 * 2**30, 136 * 2**30, 2**30, 2**29, 150000, 3600))
        c.executemany("INSERT INTO host_procs VALUES (?,?,?,?,?,?)", [
            (now - 3000, "growing", 1 * 2**30, 1, 100, 100), (now - 60, "growing", 3 * 2**30, 1, 100, 100),
            (now - 60, "leaky", 2**28, 1, 300000, 300000), (now - 3000, "steady", 2**28, 1, 50, 50),
            (now - 60, "steady", 2**28, 1, 50, 50)])
        procs = {p["name"]: p for p in analysis.host_view(c, 60)["processes"]}
        self.assertEqual(procs["growing"]["change_level"], "warn")
        self.assertEqual(procs["leaky"]["handles_level"], "bad")
        self.assertEqual((procs["steady"]["change_level"], procs["steady"]["handles_level"]), (None, None))


class StatusSurvivesVerdictTest(unittest.TestCase):
    def test_a_failing_verdict_leaves_status_intact(self):
        c = mem_db()
        self.addCleanup(c.close)
        analysis.clear_cache()
        with mock.patch.object(analysis, "verdict_view", side_effect=RuntimeError("mesh reply odd")), \
                mock.patch.object(analysis, "log"):
            st = analysis.status_view(c, 1)
        self.assertEqual((st["verdict"], st["verdict_level"]), (None, None))
        self.assertIn("internet_up", st)
        with mock.patch.object(analysis, "verdict_view", side_effect=RuntimeError("mesh reply odd")),                 mock.patch.object(analysis, "log"):
            analysis.clear_cache()
            k = analysis.kpi_view(c, 1)
        self.assertEqual(k["verdict"], {"text": None, "level": None})
        self.assertIn("internet", k)
