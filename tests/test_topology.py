import unittest

from hearth import topology as T
from tests.helpers import GW, make_series, spikes_every


class InferTest(unittest.TestCase):
    def test_detour_via_relay(self):
        # this computer -> local switch (PC, Mac) -> relay link -> TV side -> router
        spec = {"pc": (5, 3), "mac": (4.4, 2), "tv1": (7.4, 2), "tv2": (7.5, 2), GW: (10.3, 4)}
        relay_trouble = spikes_every(12, {"tv1", "tv2", GW})
        r = T.infer(make_series(spec, events=relay_trouble), ["pc", "mac", "tv1", "tv2"], GW)
        self.assertEqual(sorted(r["local"]), ["mac", "pc"])
        self.assertEqual([sorted(g) for g in r["relays"]], [["tv1", "tv2"]])
        self.assertEqual(r["branches"], [])
        self.assertTrue(r["roles"]["tv1"]["confident"])

    def test_direct_with_branch(self):
        spec = {"pc": (5.4, 3), "mac": (4.4, 2), "tv1": (9.6, 2), "tv2": (9.4, 2), GW: (7.4, 3)}
        r = T.infer(make_series(spec), ["pc", "mac", "tv1", "tv2"], GW)
        self.assertEqual(sorted(r["local"]), ["mac", "pc"])
        self.assertEqual(r["relays"], [])
        self.assertEqual([sorted(g) for g in r["branches"]], [["tv1", "tv2"]])

    def test_busy_local_pc_is_not_mistaken_for_a_relay(self):
        # the PC's own load gives it lots of spikes, but none are shared with the router
        spec = {"pc": (5.5, 3), "mac": (4.4, 2), GW: (7.4, 3)}
        own = spikes_every(15, {"pc"}, extra=60)
        r = T.infer(make_series(spec, events=own), ["pc", "mac"], GW)
        self.assertEqual(r["roles"]["pc"]["role"], T.ROLE_LOCAL)
        self.assertTrue(r["roles"]["pc"]["confident"])

    def test_measuring_machine_hiccups_are_ignored(self):
        # everything spikes at once (the computer doing the pinging stalls): no evidence either way
        spec = {"pc": (5, 3), "mac": (4.4, 2), "tv1": (7.4, 2), GW: (10.3, 4)}
        stall = spikes_every(12, {"pc", "mac", "tv1", GW})
        r = T.infer(make_series(spec, events=stall), ["pc", "mac", "tv1"], GW)
        self.assertEqual(r["roles"]["pc"]["spikes"], 0)
        self.assertEqual(r["roles"]["mac"]["role"], T.ROLE_LOCAL)

    def test_sleepy_device_is_unstable(self):
        spec = {"phone": (6, 2), "mac": (4.4, 2), GW: (8, 3)}
        naps = spikes_every(20, {"phone"}, every=60, dur=30, extra=None)
        r = T.infer(make_series(spec, events=naps), ["phone", "mac"], GW)
        self.assertIn("phone", r["unstable"])

    def test_calm_window_keeps_evidence_backed_role(self):
        spec = {"pc": (6.4, 2), "mac": (4.4, 2), GW: (7.5, 3)}
        previous = {"pc": {"role": T.ROLE_LOCAL, "confident": True, "side": "near"}}
        r = T.infer(make_series(spec), ["pc", "mac"], GW, previous=previous)
        self.assertEqual(r["roles"]["pc"]["role"], T.ROLE_LOCAL)

    def test_route_change_overrides_remembered_role(self):
        # TV side was a branch; now it answers before the router, so the route changed
        spec = {"mac": (4.4, 2), "tv1": (7.4, 2), "tv2": (7.5, 2), GW: (10.3, 4)}
        previous = {"tv1": {"role": T.ROLE_BRANCH, "confident": True, "side": "after"},
                    "tv2": {"role": T.ROLE_BRANCH, "confident": True, "side": "after"}}
        r = T.infer(make_series(spec), ["mac", "tv1", "tv2"], GW, previous=previous)
        self.assertEqual([sorted(g) for g in r["relays"]], [["tv1", "tv2"]])

    def test_not_enough_router_data(self):
        self.assertIsNone(T.infer({GW: [(0, 5.0)] * 10}, [], GW))


class MatchGroupsTest(unittest.TestCase):
    def test_ids_survive_membership_drift(self):
        old = {1: {"a", "b"}, 2: {"c", "d", "e"}}
        out, nxt = T.match_groups([["c", "d", "f"], ["a", "b", "x"], ["z"]], old, 3)
        self.assertEqual(out, [(2, ["c", "d", "f"]), (1, ["a", "b", "x"]), (3, ["z"])])
        self.assertEqual(nxt, 4)


if __name__ == "__main__":
    unittest.main()
