"""Step 3, part 2: the Overview's 24-hour timeline and "Needs attention" (hearth/overview.py)."""
import time
import unittest
from unittest import mock

from hearth import analysis, levels as lv, overview, sources, store
from tests.helpers import mem_db

NOW = float(int(time.time()) // 900 * 900 + 450)    # half way through a slot


class TimelineTest(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)
        analysis.clear_cache()

    def slots(self, episodes=()):
        with mock.patch.object(analysis, "cached", side_effect=lambda fn, conn, m, **k: {"episodes": list(episodes)}):
            return overview.timeline(self.c, NOW)

    def test_96_slots_ending_with_the_current_one(self):
        s = self.slots()
        self.assertEqual(len(s), 96)
        self.assertEqual(s[-1]["start"], int(NOW) // 900 * 900)
        self.assertEqual(s[1]["start"] - s[0]["start"], 900)

    def test_unmeasured_is_unknown_measured_is_ok(self):
        cur = int(NOW) // 900 * 900
        self.c.execute("INSERT INTO pings_1m (ts, target, n, lost, avg, max) VALUES (?, 'inet:1.1.1.1', 60, 0, 18, 20)", (cur - 900 + 60,))
        s = self.slots()
        self.assertEqual((s[-2]["level"], s[-2]["measured"]), ("ok", True))
        self.assertEqual((s[-3]["level"], s[-3]["measured"]), ("unknown", False))   # Hearth wasn't pinging

    def test_the_current_minute_counts_from_raw_pings(self):
        self.c.execute("INSERT INTO pings VALUES (?, 'inet:1.1.1.1', 18.0)", (NOW - 30,))
        self.assertTrue(self.slots()[-1]["measured"])

    def test_worst_episode_in_a_slot_and_its_starts(self):
        cur = int(NOW) // 900 * 900
        for t in (cur - 900, cur - 1800):
            self.c.execute("INSERT INTO pings_1m (ts, target, n, lost, avg, max) VALUES (?, 'inet:1.1.1.1', 60, 0, 18, 20)", (t + 60,))
        eps = [{"start": cur - 900 + 10, "end": cur - 900 + 40, "level": "warn"},
               {"start": cur - 900 + 100, "end": cur - 900 + 130, "level": "bad"},
               {"start": cur - 1800 - 30, "end": cur - 1800 + 20, "level": "warn"}]   # crosses into the slot
        s = self.slots(eps)
        self.assertEqual(s[-2]["level"], "bad")
        self.assertEqual(s[-2]["episodes"], [cur - 900 + 10, cur - 900 + 100])
        self.assertEqual(s[-3]["level"], "warn")


class AttentionTest(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)
        analysis.clear_cache()
        p = mock.patch.object(analysis, "HEARTH_STARTED", 0.0)
        p.start()
        self.addCleanup(p.stop)
        store.set_state(self.c, analysis.EPISODES_STORE_KEY, {"last_ok": time.time()})

    def items(self):
        return overview.attention(self.c, time.time())

    def test_nothing_needs_attention_is_an_empty_list(self):
        self.assertEqual(self.items(), [])

    def test_a_failing_source_and_a_pending_mesh_change_show(self):
        sources.report_error(self.c, "router", "unreachable")
        with mock.patch.object(overview.mesh, "pending_cert", return_value={"host": "192.168.1.231", "kind": "cert"}):
            items = self.items()
        texts = [i["text"] for i in items]
        self.assertTrue(any("router reading isn't working: unreachable" in t for t in texts))
        self.assertTrue(any("security certificate to confirm" in t for t in texts))
        self.assertTrue(all(i["level"] == "bad" for i in items))
        self.assertEqual({i["tab"] for i in items}, {"system", "network"})

    def test_mesh_units_and_weak_wifi(self):
        mv = {"available": True, "nodes": [
            {"mac": "aa", "name": "Bedroom", "role": "main", "online": True, "level": "ok"},
            {"mac": "bb", "name": "Office", "role": "satellite", "online": True, "level": "warn", "why": "-75 dBm",
             "findings": [{"level": "warn", "text": "Office's 6 GHz link is slow"}]},
            {"mac": "cc", "name": "Garage", "role": "satellite", "online": False, "level": "bad"}],
            "devices": [{"name": f"phone {i}", "link": "band5", "quality": "poor", "quality_why": "x"} for i in range(6)]}
        with mock.patch.object(analysis, "mesh_view", new=lambda conn, minutes=60: mv):
            items = self.items()
        texts = [i["text"] for i in items]
        self.assertEqual(texts[0], "Garage is off the mesh")                 # worst first
        self.assertIn("Office has a weak link to the mesh (-75 dBm)", texts)
        self.assertIn("Office's 6 GHz link is slow", texts)
        self.assertTrue(any(t.startswith("6 devices have weak Wi-Fi: phone 0, phone 1, phone 2, phone 3 and 2 more")
                            for t in texts))
        self.assertEqual([i["item"] for i in items if "Garage" in i["text"]], ["unit:cc"])

    def test_router_hot_or_restarted(self):
        now = time.time()
        with mock.patch.object(analysis, "router_health",
                               return_value={"available": True, "level": "bad", "why": "hot (86 °C)"}):
            self.c.execute("INSERT INTO router_stats_1h VALUES (?, 60, 60, 1, 40, 1)", (int(now - 3600) // 3600 * 3600,))
            texts = [i["text"] for i in self.items()]
        self.assertIn("The router needs a look: hot (86 °C)", texts)
        self.assertTrue(any(t.startswith("The router restarted in the last day") for t in texts))

    def test_a_restart_in_the_hour_that_began_just_over_a_day_ago_is_listed(self):
        now = time.time()
        restarted = lambda: any(t.startswith("The router restarted") for t in (i["text"] for i in self.items()))
        # the hour's row starts 24 h 30 min ago: part of it is in the last day (#71)
        self.c.execute("INSERT INTO router_stats_1h VALUES (?, 60, 60, 1, 40, 1)", (int(now) - 86400 - 1800,))
        self.assertTrue(restarted())
        self.c.execute("DELETE FROM router_stats_1h")
        self.c.execute("INSERT INTO router_stats_1h VALUES (?, 60, 60, 1, 40, 1)", (int(now) - 86400 - 5400,))   # all of it before
        self.assertFalse(restarted())

    def test_one_broken_input_becomes_one_item(self):
        sources.report_error(self.c, "router", "unreachable")

        def boom(conn, minutes=60):
            raise RuntimeError("boom")
        with mock.patch.object(analysis, "mesh_view", new=boom):
            items = self.items()
        texts = [i["text"] for i in items]
        self.assertIn("Hearth couldn't check the mesh (RuntimeError)", texts)
        self.assertTrue(any("router reading" in t for t in texts))           # the rest still show

    def test_a_pending_confirmation_shows_even_when_the_mesh_view_fails(self):
        def boom(conn, minutes=60):
            raise RuntimeError("boom")
        with mock.patch.object(overview.mesh, "pending_cert", return_value={"host": "192.168.1.231", "kind": "keys"}), \
                mock.patch.object(analysis, "mesh_view", new=boom):
            texts = [i["text"] for i in self.items()]
        self.assertTrue(any("new login keys to confirm" in t for t in texts))
        self.assertIn("Hearth couldn't check the mesh (RuntimeError)", texts)

    def test_worst_first_and_at_most_eight(self):
        hv = {"available": True, "warnings": [{"level": "warn", "text": f"warning {i}"} for i in range(12)]}
        sources.report_error(self.c, "mesh", "refused")
        with mock.patch.object(analysis, "host_view", new=lambda conn, minutes: hv):
            items = self.items()
        self.assertEqual(len(items), overview.ATTENTION_MAX)
        self.assertEqual(items[0]["level"], "bad")
        self.assertEqual([lv.rank(i["level"]) for i in items], sorted((lv.rank(i["level"]) for i in items), reverse=True))


class EndpointTest(unittest.TestCase):
    def test_a_failing_timeline_leaves_the_attention_list(self):
        c = mem_db()
        self.addCleanup(c.close)
        analysis.clear_cache()
        with mock.patch.object(overview, "timeline", side_effect=RuntimeError("boom")):
            out = overview.overview_view(c)
        self.assertEqual(out["timeline"], [])
        self.assertIn("RuntimeError", out["timeline_error"])
        self.assertIsInstance(out["attention"], list)

    def test_shape_and_separate_caches(self):
        c = mem_db()
        self.addCleanup(c.close)
        calls = []
        real = analysis.cached

        def spy(fn, conn, minutes, ttl=None):
            calls.append((fn.__name__, ttl))
            return real(fn, conn, minutes, ttl=ttl)
        with mock.patch.object(analysis, "cached", side_effect=spy):
            out = overview.overview_view(c)
        self.assertEqual(set(out), {"timeline", "timeline_error", "attention"})
        self.assertIsNone(out["timeline_error"])
        self.assertEqual(len(out["timeline"]), 96)
        self.assertIn(("timeline_view", overview.TIMELINE_TTL_S), calls)
        self.assertIn(("attention_view", overview.ATTENTION_TTL_S), calls)


if __name__ == "__main__":
    unittest.main()
