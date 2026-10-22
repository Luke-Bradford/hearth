"""Damaged data and odd inputs that used to crash a loop or skew a reading (follow-ups in #13)."""
import unittest

from hearth import collectors, router, store
from tests.helpers import mem_db


class DamagedStateTest(unittest.TestCase):
    def test_unreadable_state_row_gives_the_default(self):
        c = mem_db()
        self.addCleanup(c.close)
        c.execute("INSERT INTO state VALUES ('roles', '{not json')")
        self.assertEqual(store.get_state(c, "roles", {}), {})
        store.set_state(c, "roles", {"a": 1})
        self.assertEqual(store.get_state(c, "roles", {}), {"a": 1})

    def test_wrong_shape_gives_the_default(self):
        c = mem_db()
        self.addCleanup(c.close)
        store.set_state(c, "roles", ["a list"])            # a dict belongs here
        self.assertEqual(store.get_state(c, "roles", {}), {})
        store.set_state(c, "router_totals_ts", 1792000000.5)  # a float where the default is 0
        self.assertEqual(store.get_state(c, "router_totals_ts", 0), 1792000000.5)
        store.set_state(c, "next_group_id", True)          # a bool isn't a number here
        self.assertEqual(store.get_state(c, "next_group_id", 1), 1)
        store.set_state(c, "anything", ["x"])              # no default: no expectation
        self.assertEqual(store.get_state(c, "anything"), ["x"])
        with self.assertRaises(ValueError):
            store.set_state(c, "pins", ["x"])
            store.get_state(c, "pins", {}, strict=True)

    def test_json_or_none(self):
        self.assertEqual(collectors._json_or_none('["a"]'), ["a"])
        for bad in ("[oops", None, ""):
            self.assertIsNone(collectors._json_or_none(bad))

    def test_damaged_group_rows(self):
        self.assertEqual(collectors._group_members('["dev:a", "dev:b"]'), {"dev:a", "dev:b"})
        for bad in ('[[1]]', '[{}]', '{"a": 1}', '"x"', '[oops'):  # unhashable members too
            self.assertIsNone(collectors._group_members(bad), bad)

    def test_damaged_pins_fail_closed(self):
        # starting over would trust whatever certificate the mesh presents next
        from hearth import mesh
        c = mem_db()
        self.addCleanup(c.close)
        self.assertEqual(mesh.read_pins(c), {})                      # nothing saved yet: fine
        for bad in ("{not json", '["a list"]'):
            c.execute("INSERT OR REPLACE INTO state VALUES (?, ?)", (mesh.PINS_STATE_KEY, bad))
            with self.assertRaises(ValueError) as e:
                mesh.read_pins(c)
            self.assertIn(mesh.PINS_STATE_KEY, str(e.exception))
        c.execute("INSERT OR REPLACE INTO state VALUES (?, '{not json')", (mesh.PINS_STATE_KEY,))
        with self.assertRaises(ValueError):
            store.get_state(c, mesh.PINS_STATE_KEY, {}, strict=True)


class RouterMacTest(unittest.TestCase):
    def test_junk_macs_are_dropped(self):
        rows = [{"mac": m, "total_rx": 1, "total_tx": 1} for m in
                ("AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee", "zz:bb:cc:dd:ee:ff", "<script>", "aa:bb:cc:dd:ee:ff:00")]
        self.assertEqual([c["mac"] for c in router.parse_clients({"clients": rows})], ["aa:bb:cc:dd:ee:ff"])


class FakeRouter:
    def __init__(self, status):
        self._status = {"temp_c": 50, "load1": 0.1, "mem_used_pct": 40, **status}

    def status(self):
        return self._status


class RouterRestartBaselineTest(unittest.TestCase):
    def test_reading_without_uptime_keeps_the_baseline(self):
        c = mem_db()
        self.addCleanup(c.close)
        t = 1_792_000_000.0
        collectors._read_router_status(c, FakeRouter({"uptime_s": 86_400}), t)
        collectors._read_router_status(c, FakeRouter({"uptime_s": None}), t + 60)  # junk reading
        self.assertEqual(store.get_state(c, router.STATUS_STATE_KEY)["uptime_s"], 86_400)
        # the router then restarts: the next good reading is compared with the last good one
        collectors._read_router_status(c, FakeRouter({"uptime_s": 30}), t + 120)
        events = [d for (d,) in c.execute("SELECT detail FROM events WHERE kind='router'")]
        self.assertEqual(len(events), 1)
        self.assertIn("The router restarted", events[0])


class ConfigFileTest(unittest.TestCase):
    def load(self, text):
        import os
        import tempfile
        from unittest import mock
        from hearth import config
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: (os.remove(os.path.join(d, "config.json")), os.rmdir(d)))
        with open(os.path.join(d, "config.json"), "w", encoding="utf-8") as f:
            f.write(text)
        with mock.patch.object(config, "HERE", d):
            return config._load()

    def test_typo_gives_a_plain_message_not_a_traceback(self):
        with self.assertRaises(SystemExit) as e:
            self.load('{"web_port": 8080,}')
        self.assertIn("config.json can't be read", str(e.exception))
        with self.assertRaises(SystemExit) as e:
            self.load('[1, 2]')
        self.assertIn("JSON object", str(e.exception))

    def test_good_file_overrides_defaults(self):
        self.assertEqual(self.load('{"web_port": 9090, "_comment": "x"}')["web_port"], 9090)


class OutageRuleTest(unittest.TestCase):
    def test_sleepy_devices_missing_dont_make_an_outage(self):
        p = collectors.PollPacer(5, 60)
        for t in ("a", "b", "c"):               # three devices that keep missing: sleepy
            for i in range(6):
                p.record(t, False, i)
        self.assertTrue(all(p.sleepy(t) for t in "abc"))
        # a tick with the three sleepy ones missing again and two awake ones answering: 3 of 5
        # missed, but among devices that normally answer nobody did - not an outage, so the
        # misses count as usual
        before = len(p.recent["a"])
        p.record_tick([("a", False), ("b", False), ("c", False), ("d", True), ("e", True)], 100)
        self.assertEqual(len(p.recent["a"]), before + 1)  # the miss was recorded

    def test_most_awake_devices_missing_is_an_outage(self):
        p = collectors.PollPacer(5, 60)
        p.record_tick([(t, False) for t in "abcd"], 100)
        self.assertNotIn("a", p.recent)          # outage misses aren't held against a device


if __name__ == "__main__":
    unittest.main()
