import time
import unittest
from unittest import mock

from hearth import analysis, placement as P, store
from hearth.config import GATEWAY_STALE_SWEEPS
from tests.helpers import mem_db

# the spec's evidence from the development network, with neutral names
UNITS = {"unit-a": (4.04, "Office"), "unit-b": (6.54, "Bedroom"), "unit-c": (9.43, "Living Room")}


class PlaceTest(unittest.TestCase):
    def test_spec_fixture_pc_behind_the_office_switch(self):
        r = P.place(4.96, 2000, UNITS, None, False)
        self.assertEqual((r["placement"], r["node"]), ("timing", "unit-a"))
        self.assertIn("Office", r["why"])
        self.assertIn("4.96", r["why"])

    def test_spec_fixture_laptop_that_never_answers(self):
        self.assertEqual(P.place(None, 0, UNITS, None, False)["placement"], "unknown")

    def test_too_few_samples_is_unknown(self):
        r = P.place(4.96, P.MIN_SAMPLES - 1, UNITS, None, False)
        self.assertEqual(r["placement"], "unknown")
        self.assertIn("not enough replies", r["why"])

    def test_two_candidates_within_the_margin_is_unknown(self):
        units = {"u4": (4.0, "Four"), "u5": (5.0, "Five")}
        self.assertEqual(P.place(5.5, 500, units, None, False)["placement"], "unknown")

    def test_lower_unit_far_enough_below_picks_the_higher(self):
        units = {"u2": (2.0, "Two"), "u5": (5.0, "Five")}
        r = P.place(5.5, 500, units, None, False)       # 5.5 - 2.0 = 3.5 > margin
        self.assertEqual((r["placement"], r["node"]), ("timing", "u5"))

    def test_chosen_unit_slightly_above_the_device_is_fine(self):
        units = {"u5": (5.4, "Five"), "u9": (9.0, "Nine")}
        self.assertEqual(P.place(5.0, 500, units, None, False)["node"], "u5")     # 0.4 above: within tolerance

    def test_unit_more_than_the_tolerance_above_is_not_a_candidate(self):
        units = {"u2": (2.0, "Two"), "u6": (5.6, "Six")}
        r = P.place(5.0, 500, units, None, False)        # u6 is 0.6 above; u2 is 3.0 below > margin
        self.assertEqual(r["placement"], "unknown")

    def test_faster_than_every_unit_is_next_to_hearth(self):
        r = P.place(1.0, 500, UNITS, "unit-a", False)
        self.assertEqual((r["placement"], r["node"]), ("timing", "unit-a"))
        self.assertIn("same switch or segment as this computer", r["why"])

    def test_role_local_is_next_to_hearth(self):
        self.assertEqual(P.place(7.0, 500, UNITS, "unit-b", True)["node"], "unit-b")

    def test_next_to_hearth_without_hearths_unit_is_unknown(self):
        self.assertEqual(P.place(1.0, 500, UNITS, None, False)["placement"], "unknown")
        self.assertEqual(P.place(7.0, 500, UNITS, None, True)["placement"], "unknown")

    def test_synthetic_layout_with_hearth_behind_a_far_unit(self):
        # Hearth sits behind what was the "far" unit: floors are relative to Hearth, so that unit
        # is now the near one and the others are slower
        units = {"far": (3.0, "Garage"), "mid": (6.5, "Hall"), "near": (9.0, "Office")}
        self.assertEqual(P.place(3.8, 500, units, "far", False)["node"], "far")
        self.assertEqual(P.place(9.6, 500, units, "far", False)["node"], "near")

    def test_unit_without_a_floor_is_ignored(self):
        # the caller leaves units without a floor out of unit_floors: nothing to compare with
        self.assertEqual(P.place(4.96, 500, {"unit-a": (4.04, "Office")}, None, False)["node"], "unit-a")
        self.assertEqual(P.place(4.96, 500, {}, None, False)["placement"], "unknown")


OFFICE, BEDROOM = "20:e1:5d:00:00:01", "20:e1:5d:00:00:02"
PC, LAPTOP, ROUTER = "aa:00:00:00:00:01", "aa:00:00:00:00:02", "aa:00:00:00:00:fe"


class MeshPlacementTest(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)
        now = time.time()
        store.set_state(self.c, "mesh", {"ts": now, "nodes": [
            {"mac": OFFICE, "name": "Office", "ip": "192.168.1.2", "role": "satellite", "online": True,
             "backhaul": "wireless", "rssi": {"band5": -55}},
            {"mac": BEDROOM, "name": "Bedroom", "ip": "192.168.1.3", "role": "main", "online": True,
             "backhaul": "wired"}],
            "clients": [{"mac": "bb:00:00:00:00:09", "ip": "192.168.1.9", "node": OFFICE, "link": "band5"}]})
        self.c.executemany("INSERT INTO devices (ip, mac, name, first_seen, last_seen, online) VALUES (?,?,?,?,?,1)",
                           [("192.168.1.10", PC, "pc-1", now, now), ("192.168.1.11", LAPTOP, "laptop-1", now, now),
                            ("192.168.1.254", ROUTER, "router", now, now),
                            ("192.168.1.2", OFFICE, "office", now, now), ("192.168.1.9", "bb:00:00:00:00:09", "phone", now, now)])
        rows = []
        for i in range(600):                                   # 50 minutes of 5-second pings
            t = now - 3000 + i * 5
            rows += [(t, f"dev:{OFFICE}", 4.04 + (i % 7) * 0.3), (t, f"dev:{BEDROOM}", 6.54 + (i % 5) * 0.3),
                     (t, f"dev:{PC}", 4.96 + (i % 9) * 0.3), (t, f"dev:{LAPTOP}", None)]
        self.c.executemany("INSERT INTO pings VALUES (?,?,?)", rows)
        analysis.clear_cache()

    def view(self):
        with mock.patch.object(analysis, "_gateway_ip", return_value="192.168.1.254"), \
                mock.patch.object(analysis, "_my_ip", return_value="192.168.1.60"):
            return analysis.mesh_view(self.c, 60)

    def test_unlisted_devices_are_placed_or_unknown(self):
        v = self.view()
        un = {d["name"]: d for d in v["unlisted"]}
        self.assertEqual((un["pc-1"]["placement"], un["pc-1"]["node"]), ("timing", OFFICE))
        self.assertEqual(un["laptop-1"]["placement"], "unknown")
        self.assertNotIn("router", un)                        # the router itself is never "unlisted"
        self.assertNotIn("office", un)                        # nor a mesh unit
        self.assertNotIn("phone", un)                         # listed by the mesh
        self.assertTrue(all(d["placement"] == "mesh" for d in v["devices"]))

    def test_device_floors(self):
        floors = analysis.device_floors(self.c, time.time())
        self.assertAlmostEqual(floors[f"dev:{PC}"][0], 4.96, places=1)
        self.assertEqual(floors[f"dev:{PC}"][1], 600)
        self.assertNotIn(f"dev:{LAPTOP}", floors)             # never answered: no floor


class PlacementReviewTest(MeshPlacementTest):
    """Cases from the whole-branch review of #38 part 4."""

    def add_device(self, ip, mac, name, online=1, last_seen=None):
        now = time.time()
        self.c.execute("INSERT OR REPLACE INTO devices (ip, mac, name, first_seen, last_seen, online) VALUES (?,?,?,?,?,?)",
                       (ip, mac, name, now, last_seen or now, online))

    def test_a_sleeping_laptop_the_router_calls_offline_is_not_unlisted(self):
        # #122: never answers ping, still in ARP (its card answers while it sleeps), the router says
        # offline - asleep, so not "Location unknown"; stale router rows aren't evidence
        store.save_router_clients(self.c, time.time() - 3600, [{"mac": LAPTOP, "ip": "192.168.1.11", "name": None, "online": False}])
        self.assertIn("laptop-1", {d["name"] for d in self.view()["unlisted"]})
        analysis.clear_cache()
        store.save_router_clients(self.c, time.time(), [{"mac": LAPTOP, "ip": "192.168.1.11", "name": None, "online": False}])
        self.assertNotIn("laptop-1", {d["name"] for d in self.view()["unlisted"]})

    def test_unit_under_another_mac_is_not_unlisted(self):
        self.add_device("192.168.1.3", "cc:00:00:00:00:03", "bedroom-radio")   # Bedroom's IP, a radio MAC
        self.assertNotIn("cc:00:00:00:00:03", {d["mac"] for d in self.view()["unlisted"]})

    def test_listed_client_under_another_mac_is_not_unlisted(self):
        self.c.execute("UPDATE devices SET mac=? WHERE ip=?", ("dd:00:00:00:00:09", "192.168.1.9"))
        self.assertNotIn("phone", {d["name"] for d in self.view()["unlisted"]})

    def test_one_entry_per_device_the_online_row_winning(self):
        # the same MAC online at a second address (both rows online): one entry, the newest row
        self.add_device("192.168.1.99", PC, "pc-1 old", online=1, last_seen=time.time() - 3600)
        entries = [d for d in self.view()["unlisted"] if d["mac"] == PC]
        self.assertEqual([d["ip"] for d in entries], ["192.168.1.10"])

    def test_router_known_from_discovery_is_never_unlisted(self):
        store.set_state(self.c, "gateway_ip", {"ip": "192.168.1.254", "ts": time.time()})
        with mock.patch.object(analysis, "_my_ip", return_value="192.168.1.60"), \
                mock.patch.dict(analysis.CFG, {"gateway": None}), \
                mock.patch.object(analysis.net, "default_gateway", return_value=None):
            v = analysis.mesh_view(self.c, 60)                 # no patched _gateway_ip: the saved one
        self.assertNotIn("router", {d["name"] for d in v["unlisted"]})

    def test_failed_gateway_lookup_is_not_cached(self):
        with mock.patch.dict(analysis._gw_cache, {"ts": 0.0, "ip": None}), \
                mock.patch.dict(analysis.CFG, {"gateway": None}), \
                mock.patch.object(analysis.net, "default_gateway", side_effect=[None, "192.168.1.254"]) as dg:
            self.assertIsNone(analysis._gateway_ip(self.c))
            self.assertEqual(analysis._gateway_ip(self.c), "192.168.1.254")   # retried, not cached
        self.assertEqual(dg.call_count, 2)

    def test_offline_unit_or_unit_with_few_samples_isnt_a_candidate(self):
        snap = store.get_state(self.c, "mesh")
        snap["nodes"][0]["online"] = False                     # Office offline: its 6 h floor is stale
        store.set_state(self.c, "mesh", snap)
        pc = next(d for d in self.view()["unlisted"] if d["name"] == "pc-1")
        self.assertNotEqual(pc.get("node"), OFFICE)


class PlacementReview2Test(MeshPlacementTest):
    """Cases from the PR review of #38 part 4 (#62)."""

    add_device = PlacementReviewTest.add_device

    def test_floors_match_pct_for_any_count_and_ties(self):
        now = time.time()
        for n in (1, 2, 3, 21, 22, 41, 1000):
            vals = [round(1.0 + (i * 7919 % n) * 0.13 + (i % 3) * 0.5, 2) for i in range(n)]   # unsorted, ties
            self.c.executemany("INSERT INTO pings VALUES (?,?,?)", [(now - i, f"dev:n{n}", v) for i, v in enumerate(vals)])
            self.assertEqual(analysis.device_floors(self.c, now)[f"dev:n{n}"], (analysis.pct(vals, P.FLOOR_PCT), n))

    def test_one_view_at_two_freshnesses_is_two_cache_entries(self):
        calls = []
        def view(conn, minutes):
            calls.append(minutes)
            return len(calls)
        self.assertEqual(analysis.cached(view, self.c, 999, ttl=300), 1)
        self.assertEqual(analysis.cached(view, self.c, 999, ttl=1), 2)        # not the 300 s entry

    def test_unit_floor_found_whatever_the_mesh_mac_case(self):
        snap = store.get_state(self.c, "mesh")
        for n in snap["nodes"]:
            n["mac"] = n["mac"].upper()
        for c in snap["clients"]:
            c["node"] = c["node"].upper()
        store.set_state(self.c, "mesh", snap)
        pc = next(d for d in self.view()["unlisted"] if d["name"] == "pc-1")
        self.assertEqual((pc["placement"], pc["node"]), ("timing", OFFICE.upper()))

    def test_saved_gateway_with_wrong_types_falls_back_to_the_route(self):
        self.assertEqual(self.gateway({"ip": "192.168.1.254", "ts": "yesterday"}), "192.168.1.1")
        self.assertEqual(self.gateway({"ip": ["192.168.1.254"], "ts": time.time()}), "192.168.1.1")

    def test_floors_on_sqlite_without_window_functions(self):
        now = time.time()
        with mock.patch.object(analysis.sqlite3, "sqlite_version_info", (3, 24, 0)), \
                mock.patch.object(analysis, "pct", wraps=analysis.pct) as p:
            old = analysis.device_floors(self.c, now)
        self.assertTrue(p.called)                             # the Python way, not the window query
        self.assertEqual(old, analysis.device_floors(self.c, now))
        self.assertEqual(old[f"dev:{PC}"][1], 600)

    def test_floors_worked_out_every_few_minutes_not_every_request(self):
        real = analysis.device_floors
        with mock.patch.object(analysis, "device_floors", side_effect=real) as df:
            t0 = time.time()
            for dt in (0, 120, P.FLOOR_REFRESH_S - 10, P.FLOOR_REFRESH_S + 10):
                # analysis's own clock only, not the shared time module
                with mock.patch.object(analysis, "time", mock.Mock(wraps=time, time=mock.Mock(return_value=t0 + dt))):
                    self.view()
        self.assertEqual(df.call_count, 2)                    # first call, then once the refresh is due

    def gateway(self, saved, cfg=None, route="192.168.1.1"):
        store.set_state(self.c, "gateway_ip", saved)
        with mock.patch.dict(analysis._gw_cache, {"ts": 0.0, "ip": None}), \
                mock.patch.dict(analysis.CFG, {"gateway": cfg}), \
                mock.patch.object(analysis.net, "default_gateway", return_value=route):
            return analysis._gateway_ip(self.c)

    def test_config_gateway_overrides_the_saved_one(self):
        self.assertEqual(self.gateway({"ip": "192.168.1.254", "ts": time.time()}, cfg="10.0.0.1"), "10.0.0.1")

    def test_stale_or_unreadable_saved_gateway_falls_back_to_the_route(self):
        old = time.time() - (GATEWAY_STALE_SWEEPS * analysis.CFG["discovery_interval_s"] + 60)
        self.assertEqual(self.gateway({"ip": "192.168.1.254", "ts": old}), "192.168.1.1")
        self.assertEqual(self.gateway("192.168.1.254"), "192.168.1.1")        # the earlier, bare format
        self.assertEqual(self.gateway({"ip": "192.168.1.254", "ts": time.time()}), "192.168.1.254")

    def test_hearths_unit_matched_whatever_the_mac_case(self):
        snap = store.get_state(self.c, "mesh")
        snap["clients"].append({"mac": "ee:00:00:00:00:60", "ip": "192.168.1.60", "node": OFFICE.upper(), "link": "wired"})
        store.set_state(self.c, "mesh", snap)
        self.add_device("192.168.1.20", "aa:00:00:00:00:20", "fast-1")
        now = time.time()
        self.c.executemany("INSERT INTO pings VALUES (?,?,?)",
                           [(now - i * 5, "dev:aa:00:00:00:00:20", 1.0) for i in range(200)])
        fast = next(d for d in self.view()["unlisted"] if d["name"] == "fast-1")
        self.assertEqual((fast["placement"], fast["node"]), ("timing", OFFICE))   # the unit's own spelling
        self.assertIn("Office", fast["why"])

    def test_device_whose_best_row_is_skipped_isnt_drawn_from_another_row(self):
        self.add_device("192.168.1.3", PC, "pc-1 at a unit's address", last_seen=time.time() + 10)
        self.assertNotIn(PC, {d["mac"] for d in self.view()["unlisted"]})


class PlaceBoundaryTest(unittest.TestCase):
    def test_exact_margin_and_tolerance_boundaries(self):
        # 4.03 - 2.03 is 2.0000000000000004 in floating point: still within the 2.0 ms margin
        self.assertGreater(4.03 - 2.03, 2.0)
        self.assertEqual(P.place(4.03, 500, {"u": (2.03, "U")}, None, False)["node"], "u")
        # 2.14 - 1.64 is just over 0.5 in floating point: a unit exactly 0.5 ms above is a candidate
        self.assertGreater(2.14 - 1.64, 0.5)
        self.assertEqual(P.place(1.64, 500, {"u": (2.14, "U")}, None, False)["node"], "u")

    def test_hearths_unit_named_even_without_a_floor(self):
        r = P.place(1.0, 500, {"other": (4.0, "Other")}, "mine", False, names={"mine": "Office", "other": "Other"})
        self.assertIn("on Office", r["why"])
