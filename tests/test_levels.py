import time
import unittest
from unittest import mock

from hearth import analysis, levels as L
from tests.helpers import mem_db


def stats(loss=0.0, p50=18.0, p95=25.0, samples=100):
    return {"samples": samples, "loss_pct": loss, "p50": p50, "p95": p95}


class LinkLevelTest(unittest.TestCase):
    def test_no_data_is_unknown(self):
        for s in (None, {}, {"samples": 0}):
            self.assertEqual(L.link_level(s)["level"], L.UNKNOWN)

    def test_all_lost_is_bad(self):
        r = L.link_level(stats(loss=100.0, p50=None, p95=None))
        self.assertEqual(r["level"], L.BAD)
        self.assertIn("no replies", r["why"])

    def test_thresholds(self):
        self.assertEqual(L.link_level(stats())["level"], L.OK)
        self.assertEqual(L.link_level(stats(loss=1.5))["level"], L.WARN)           # > LOSS_FAIR
        self.assertEqual(L.link_level(stats(loss=6.0))["level"], L.BAD)            # > LOSS_POOR
        self.assertEqual(L.link_level(stats(p95=18 + 41))["level"], L.WARN)        # > SLOW_FAIR above typical
        self.assertEqual(L.link_level(stats(p95=18 + 101))["level"], L.BAD)        # > SLOW_POOR above typical
        self.assertEqual(L.link_level(stats(p95=18 + 40))["level"], L.OK)          # boundary: not above

    def test_all_lost_with_a_stray_p95_is_bad(self):
        self.assertEqual(L.link_level(stats(loss=100.0, p95=30))["level"], L.BAD)

    def test_why_explains(self):
        self.assertIn("1.5% lost", L.link_level(stats(loss=1.5))["why"])
        self.assertIn("+101 ms", L.link_level(stats(p95=119))["why"])


class DeviceLevelTest(unittest.TestCase):
    def test_grades_map_to_levels(self):
        node = stats(p95=10)
        self.assertEqual(L.device_level(stats(p95=20), node)["level"], L.OK)
        self.assertEqual(L.device_level(stats(p95=60), node)["level"], L.WARN)   # +50 over its unit
        self.assertEqual(L.device_level(stats(p95=200), node)["level"], L.BAD)
        self.assertEqual(L.device_level(stats(), node, sleepy=True)["level"], L.UNKNOWN)

    def test_no_data_is_unknown(self):
        self.assertEqual(L.device_level(None, None)["level"], L.UNKNOWN)

    def test_silent_for_an_hour_is_bad_even_if_sleepy(self):
        # same order as mesh.device_quality: no answers at all is a problem, dozing or not
        self.assertEqual(L.device_level(stats(loss=100.0, p50=None, p95=None), None, sleepy=True)["level"], L.BAD)


class SimpleLevelsTest(unittest.TestCase):
    def test_signal(self):
        self.assertEqual([L.signal_level(v)["level"] for v in (-50, -65, -66, -75, -76)],
                         [L.OK, L.OK, L.WARN, L.WARN, L.BAD])
        self.assertEqual(L.signal_level(None)["level"], L.UNKNOWN)
        self.assertIn("-76 dBm", L.signal_level(-76)["why"])

    def test_temp_levels(self):
        self.assertEqual([L.temp_level(t, 75, 85)["level"] for t in (60, 75, 84.9, 85)], [L.OK, L.WARN, L.WARN, L.BAD])
        self.assertEqual(L.temp_level(None, 75, 85)["level"], L.UNKNOWN)

    def test_channel(self):
        self.assertEqual([L.channel_level(u)["level"] for u in (10, 40, 59, 60)], [L.OK, L.WARN, L.WARN, L.BAD])
        self.assertEqual(L.channel_level(None)["level"], L.UNKNOWN)

    def test_worst_of_names_the_worst(self):
        r = L.worst_of([L.result(L.OK, "a"), L.result(L.BAD, "b"), L.result(L.WARN, "c")])
        self.assertEqual(r, {"level": L.BAD, "why": "b"})
        self.assertEqual(L.worst_of([])["level"], L.UNKNOWN)

    def test_worst(self):
        self.assertEqual(L.worst([L.OK, L.WARN, L.UNKNOWN]), L.WARN)
        self.assertEqual(L.worst([L.OK, L.BAD]), L.BAD)
        self.assertEqual(L.worst([L.UNKNOWN, L.OK]), L.OK)
        self.assertEqual(L.worst([]), L.UNKNOWN)


class InternetLevelTest(unittest.TestCase):
    def st(self, loss=0.0, p50=16.0, p95=30.0, up=True):
        return {"loss_pct_5m": loss, "internet_ms": p50, "internet_p95_ms": p95, "internet_up": up}

    def test_levels(self):
        self.assertEqual(L.internet_level(self.st())["level"], L.OK)
        self.assertEqual(L.internet_level(self.st(p95=101))["level"], L.WARN)    # +85 ms
        self.assertEqual(L.internet_level(self.st(loss=6.0))["level"], L.BAD)
        self.assertEqual(L.internet_level(self.st(loss=100.0, p50=None, p95=None, up=False))["level"], L.BAD)

    def test_no_data_is_unknown(self):
        self.assertEqual(L.internet_level(self.st(loss=None, p50=None, p95=None, up=False))["level"], L.UNKNOWN)
        self.assertEqual(L.internet_level(self.st(loss=None, p50=None, p95=None, up=True))["level"], L.UNKNOWN)
        self.assertEqual(L.internet_level(self.st(loss=0.0, p50=None, p95=None, up=True))["level"], L.UNKNOWN)

    def test_down_with_some_earlier_replies_is_bad(self):
        r = L.internet_level({**self.st(loss=40.0, up=False), "internet_measured": True})
        self.assertEqual((r["level"], r["why"]), (L.BAD, "no answers from the internet right now"))

    def test_a_short_gap_in_pings_is_not_an_outage(self):
        # Hearth restarting: pings earlier in the 5 minutes, none in the last 15 s
        r = L.internet_level({**self.st(loss=0.0, up=False), "internet_measured": False})
        self.assertEqual(r["level"], L.UNKNOWN)


class DeviceQualityUnchangedTest(unittest.TestCase):
    CASES = [
        ((None, None, False), (None, "not measured yet")),
        (({"samples": 0}, None, False), (None, "not measured yet")),
        (({"samples": 10, "loss_pct": 100, "p95": None}, None, False), ("poor", "no answers in the last hour (100% lost)")),
        (({"samples": 10, "loss_pct": 0, "p95": 30, "p50": 10}, {"p95": 10}, True),
         ("sleepy", "answers erratically - usually power saving (phones, tablets), not a bad connection")),
        (({"samples": 10, "loss_pct": 2, "p95": 30}, None, False),
         ("fair", "2% lost (its mesh unit isn't measured, so latency isn't judged)")),
        (({"samples": 10, "loss_pct": 0, "p95": 60}, {"p95": 10}, False), ("fair", "0% lost, slowest 5% 60 ms (+50 ms vs its mesh unit)")),
        (({"samples": 10, "loss_pct": 0, "p95": 200}, {"p95": 10}, False), ("poor", "0% lost, slowest 5% 200 ms (+190 ms vs its mesh unit)")),
        (({"samples": 10, "loss_pct": 6, "p95": 20}, {"p95": 10}, False), ("poor", "6% lost, slowest 5% 20 ms (+10 ms vs its mesh unit)")),
        (({"samples": 10, "loss_pct": 0, "p95": 15}, {"p95": 10}, False), ("good", "0% lost, slowest 5% 15 ms (+5 ms vs its mesh unit)")),
    ]

    def test_same_grades_and_reasons_as_before(self):
        from hearth import mesh
        for args, expected in self.CASES:
            self.assertEqual(mesh.device_quality(*args), expected, args)


class SummaryLevelsTest(unittest.TestCase):
    def test_every_hop_device_and_core_target_has_a_level(self):
        c = mem_db()
        self.addCleanup(c.close)
        now = time.time()
        rows = []
        for i in range(120):
            t = now - 120 + i
            rows += [(t, "gateway", 2.0), (t, "inet:1.1.1.1", 18.0), (t, "dev:aa:bb:cc:00:00:01", None)]
        c.executemany("INSERT INTO pings VALUES (?,?,?)", rows)
        analysis.clear_cache()
        s = analysis.summary(c, 5)
        self.assertEqual(s["core"]["gateway"]["level"], L.OK)
        dev = next(d for d in s["devices"] if d["id"] == "dev:aa:bb:cc:00:00:01")
        self.assertEqual((dev["level"], "no replies" in dev["why"]), (L.BAD, True))
        for h in s["hops"]:
            self.assertIn(h["level"], (L.OK, L.WARN, L.BAD, L.UNKNOWN))

    def test_hop_takes_its_worst_member(self):
        stats = {"a": {"samples": 10, "p50": 5, "p95": 8, "loss_pct": 0},
                 "b": {"samples": 10, "p50": None, "p95": None, "loss_pct": 100.0}}   # dead, not responding
        r = analysis.group_level(["a", "b"], stats, {"b": "Office Deco"})
        self.assertEqual(r["level"], L.BAD)
        self.assertIn("Office Deco", r["why"])
        self.assertEqual(analysis.group_level(["a"], stats, {})["level"], L.OK)
        self.assertEqual(analysis.group_level([], stats, {})["level"], L.UNKNOWN)


class VerdictTest(unittest.TestCase):
    def test_all_fine(self):
        v = analysis.verdict_from({"level": L.OK}, 0, {"level": L.OK}, {"level": L.OK}, {"level": L.OK, "poor": []})
        self.assertEqual(v, {"level": L.OK, "text": "Your internet is fine."})

    def test_one_weak_device(self):
        v = analysis.verdict_from({"level": L.OK}, 0, {"level": L.OK}, {"level": L.OK},
                                  {"level": L.WARN, "poor": [{"name": "Watch"}]})
        self.assertEqual(v, {"level": L.WARN, "text": "Your internet is fine. 1 device has weak WiFi."})

    def test_internet_down_leads(self):
        v = analysis.verdict_from({"level": L.BAD, "up": False}, 0, {"level": L.OK}, {"level": L.OK}, {"level": L.OK, "poor": []})
        self.assertEqual(v["text"], "Your internet is down.")
        self.assertEqual(v["level"], L.BAD)

    def test_verdict_orders_and_caps(self):
        v = analysis.verdict_from({"level": L.WARN, "up": True}, 2,
                                  {"level": L.BAD, "temp_c": 88},
                                  {"level": L.BAD, "name": "Office", "backhaul": "offline"},
                                  {"level": L.WARN, "poor": [{"name": "a"}, {"name": "b"}]})
        self.assertEqual(v["level"], L.BAD)
        # the internet first, then at most two more, worst first (ties keep this order); the
        # third issue (2 devices with weak WiFi, only warn) is left out
        self.assertEqual(v["text"], "Your internet is slow at times; 2 outages or problems in the last hour. "
                                    "Office is off the mesh. The router is hot (88 °C).")

    def test_no_pings_yet_is_not_an_outage(self):
        # an empty database: internet_up is False (no pings in 15 s) but nothing was measured
        v = analysis.verdict_from({"level": L.UNKNOWN, "up": False}, 0, {"level": L.WARN, "temp_c": 80},
                                  {"level": L.OK}, {"level": L.OK, "poor": []})
        self.assertFalse(v["text"].startswith("Your internet is down"))
        self.assertEqual(v["text"], "Your internet hasn't been measured yet. The router is hot (80 °C).")

    def test_recent_trouble_but_nothing_measured_now(self):
        v = analysis.verdict_from({"level": L.UNKNOWN, "up": False}, 1, {"level": L.OK}, {"level": L.OK},
                                  {"level": L.OK, "poor": []})
        self.assertEqual(v, {"level": L.WARN, "text": "Your internet hasn't been measured in the last few minutes; "
                                                      "1 outage or problem earlier in the hour."})

    def test_fine_now_after_an_outage_earlier(self):
        v = analysis.verdict_from({"level": L.OK, "up": True}, 1, {"level": L.OK}, {"level": L.OK},
                                  {"level": L.OK, "poor": []})
        self.assertEqual(v, {"level": L.WARN, "text": "Your internet is fine now; 1 outage or problem in the last hour."})

    def test_nothing_measured(self):
        v = analysis.verdict_from({"level": L.UNKNOWN}, 0, {"level": L.UNKNOWN}, {"level": L.UNKNOWN}, {"level": L.UNKNOWN})
        self.assertEqual(v, {"level": L.UNKNOWN, "text": "Hearth is still measuring."})

    def test_verdict_from_a_real_database(self):
        # the tiles really carry the fields verdict_from reads (up, name/backhaul, temp_c, poor)
        c = mem_db()
        self.addCleanup(c.close)
        now = time.time()
        rows = []
        for i in range(60):
            rows += [(now - 60 + i, "inet:1.1.1.1", 18.0), (now - 60 + i, "inet:8.8.8.8", 19.0), (now - 60 + i, "gateway", 2.0)]
        c.executemany("INSERT INTO pings VALUES (?,?,?)", rows)
        # a reading 30 s old is fresh (ROUTER_STATS_MAX_AGE_S = 600) and 90 °C is past the red
        # limit; the limits are set explicitly so a local config.json can't change the outcome
        c.execute("INSERT INTO router_stats VALUES (?,?,?,?,?)", (now - 30, 90.0, 3600, 0.1, 40))
        analysis.clear_cache()
        limits = mock.patch.dict(analysis.CFG, {"router_temp_warn_c": 75, "router_temp_bad_c": 85})
        limits.start()
        self.addCleanup(limits.stop)
        v = analysis.verdict_view(c, 60)
        self.assertEqual(v["level"], L.BAD)
        self.assertEqual(v["text"], "Your internet is fine. The router is hot (90 °C).")
        st = analysis.status_view(c, 60)
        self.assertEqual((st["verdict"], st["verdict_level"]), (v["text"], v["level"]))

    def test_through_the_real_cache_wiring(self):
        # /api/status and /api/kpi as web.py calls them: cached() nesting verdict_view, mesh_view
        # and incidents inside status_view / kpi_view must neither deadlock nor disagree
        from hearth.web import STATUS_KEY   # module level in web.py (= 1); tests already import hearth.web
        c = mem_db()
        self.addCleanup(c.close)
        now = time.time()
        c.executemany("INSERT INTO pings VALUES (?,?,?)",
                      [(now - 60 + i, t, 18.0) for i in range(60) for t in ("inet:1.1.1.1", "inet:8.8.8.8", "gateway")])
        analysis.clear_cache()
        st = analysis.cached(analysis.status_view, c, STATUS_KEY)
        k = analysis.cached(analysis.kpi_view, c, STATUS_KEY)
        self.assertEqual(st["verdict"], k["verdict"]["text"])
        self.assertEqual(st["verdict"], "Your internet is fine.")

    def test_router_level_without_a_temperature_doesnt_crash(self):
        v = analysis.verdict_from({"level": L.OK}, 0, {"level": L.WARN, "temp_c": None, "why": "odd reading"},
                                  {"level": L.OK}, {"level": L.OK, "poor": []})
        self.assertEqual(v["text"], "Your internet is fine. The router needs a look (odd reading).")
