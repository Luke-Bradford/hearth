"""Part 3 of step 2 (#64): where each device was, recorded when it changes."""
import http.client
import os
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

from hearth import analysis, collectors, store
from tests.helpers import mem_db, page_code, run_mesh_loop

OFFICE, BEDROOM = "20:e1:5d:00:00:01", "20:e1:5d:00:00:02"
PC = "dev:aa:00:00:00:00:01"


def places(c):
    return c.execute("SELECT ts, device, node, how FROM device_places ORDER BY device, ts").fetchall()


class PlacesNowTest(unittest.TestCase):
    def test_from_the_maps_answer(self):
        view = {"available": True,
                "devices": [{"id": "dev:a", "node": OFFICE}],
                "unlisted": [{"id": "dev:b", "placement": "timing", "node": BEDROOM},
                             {"id": "dev:c", "placement": "unknown", "node": None}]}
        self.assertEqual(analysis.places_now(view), {"dev:a": (OFFICE, "mesh"), "dev:b": (BEDROOM, "timing"),
                                                     "dev:c": (None, "unknown")})
        self.assertEqual(analysis.places_now({"available": False}), {})


class RecordTest(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)
        self.cand = {}

    def read(self, t, place):
        self.cand = collectors.record_places(self.c, {PC: place} if place else {}, t, self.cand)

    def test_first_place_at_once_then_changes_need_two_readings(self):
        self.read(100, (OFFICE, "mesh"))
        self.assertEqual(places(self.c), [(100, PC, OFFICE, "mesh")])     # first place: at once
        self.read(400, (OFFICE, "mesh"))
        self.assertEqual(len(places(self.c)), 1)                           # unchanged: nothing
        self.read(700, (BEDROOM, "mesh"))                                  # mesh-to-mesh: waits too
        self.assertEqual(len(places(self.c)), 1)
        self.read(1000, (BEDROOM, "mesh"))
        self.assertEqual(places(self.c)[-1], (700, PC, BEDROOM, "mesh"))  # dated when first seen

    def test_a_single_flip_writes_nothing(self):
        self.read(100, (OFFICE, "mesh"))
        for t, p in ((400, (None, "unknown")), (700, (OFFICE, "mesh")), (1000, (BEDROOM, "timing")),
                     (1300, (OFFICE, "mesh"))):
            self.read(t, p)
        self.assertEqual(len(places(self.c)), 1)

    def test_a_different_reading_restarts_the_count(self):
        self.read(100, (OFFICE, "mesh"))        # A in force
        self.read(400, (BEDROOM, "mesh"))       # candidate B
        self.read(700, (None, "unknown"))       # C: replaces B, count restarts
        self.assertEqual(len(places(self.c)), 1)
        self.read(1000, (None, "unknown"))      # C holds
        self.assertEqual(places(self.c)[-1], (700, PC, None, "unknown"))

    def test_going_offline_drops_a_pending_change(self):
        self.read(100, (OFFICE, "mesh"))
        self.read(400, (BEDROOM, "mesh"))       # candidate
        self.read(700, None)                    # not online: dropped, and nothing written
        self.read(10000, (BEDROOM, "mesh"))     # hours later: a new first reading of the change
        self.assertEqual(len(places(self.c)), 1)
        self.read(10300, (BEDROOM, "mesh"))
        self.assertEqual(places(self.c)[-1], (10000, PC, BEDROOM, "mesh"))

    def test_pending_changes_are_returned_not_changed_in_place(self):
        # the caller adopts them only once the rows commit: a rolled-back write leaves them as they were
        self.read(100, (OFFICE, "mesh"))
        before = dict(self.cand)
        after = collectors.record_places(self.c, {PC: (BEDROOM, "mesh")}, 400, before)
        self.assertEqual(before, {})                        # untouched
        self.assertEqual(after, {PC: (BEDROOM, "mesh", 400)})

    def test_pruning_keeps_the_place_in_force_at_the_cutoff(self):
        now = time.time()
        cutoff = now - store.ROLLUP_DAYS * 86400
        self.c.executemany("INSERT INTO device_places VALUES (?,?,?,?)", [
            (cutoff - 300, PC, OFFICE, "mesh"), (cutoff - 100, PC, BEDROOM, "mesh"), (now - 50, PC, OFFICE, "mesh"),
            (cutoff - 500, "dev:old", None, "unknown")])
        self.c.execute("INSERT INTO devices (ip, mac, online, last_seen) VALUES ('192.168.1.50', 'aa:00:00:00:00:99', 0, ?)",
                       (now,))
        self.c.execute("INSERT INTO device_places VALUES (?,?,?,?)", (cutoff - 900, "dev:aa:00:00:00:00:99", None, "unknown"))
        self.c.execute("INSERT INTO router_clients (mac, ip, online, last_seen) VALUES ('aa:00:00:00:00:77', '192.168.1.77', 1, ?)",
                       (now,))
        self.c.execute("INSERT INTO device_places VALUES (?,?,?,?)", (cutoff - 800, "dev:aa:00:00:00:00:77", OFFICE, "mesh"))
        store.prune(self.c, now)
        # PC: the place in force at the cutoff is kept; dev:old (gone from the device list, nothing
        # newer) goes entirely; a device still listed keeps its old last row
        self.assertEqual([(d, n) for _, d, n, _ in places(self.c)],
                         [(PC, BEDROOM), (PC, OFFICE), ("dev:aa:00:00:00:00:77", OFFICE),
                          ("dev:aa:00:00:00:00:99", None)])     # one only the router knows is kept too


class HistoryTest(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)
        now = time.time()
        store.set_state(self.c, "mesh", {"ts": now, "nodes": [{"mac": OFFICE, "name": "Office"},
                                                              {"mac": BEDROOM, "name": "Bedroom"}], "clients": []})
        self.c.executemany("INSERT INTO device_places VALUES (?,?,?,?)", [
            (now - 5000, PC, OFFICE, "mesh"), (now - 3000, PC, BEDROOM, "timing"), (now - 1000, PC, None, "unknown")])

    def test_changes_in_range_and_the_place_at_its_start(self):
        out = analysis.device_places(self.c, PC, 30)          # 30 minutes back: Bedroom was in force then
        self.assertEqual([(p["node_name"], p["how"]) for p in out["places"]],
                         [("Bedroom", "timing"), (None, "unknown")])
        self.assertEqual(len(analysis.device_places(self.c, PC, 1440)["places"]), 3)

    def test_a_unit_gone_from_the_mesh_is_named_as_such(self):
        self.c.execute("INSERT INTO device_places VALUES (?,?,?,?)", (time.time() - 10, PC, "20:e1:5d:00:00:09", "mesh"))
        last = analysis.device_places(self.c, PC, 60)["places"][-1]
        self.assertEqual(last["node_name"], "unit no longer in the mesh")


class EndpointTest(unittest.TestCase):
    def setUp(self):
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), __import__("hearth.web", fromlist=["Handler"]).Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.addCleanup(os.remove, self.path)
        p = mock.patch.object(store, "DB_PATH", self.path)
        p.start()
        self.addCleanup(p.stop)
        store.init_db()                                    # the schema with its migrations
        c = store.db()
        c.execute("INSERT INTO device_places VALUES (?,?,?,?)", (time.time() - 10, PC, OFFICE, "mesh"))
        c.commit()
        c.close()

    def get(self, query):
        conn = http.client.HTTPConnection("127.0.0.1", self.srv.server_address[1], timeout=5)
        self.addCleanup(conn.close)   # closed even when an assertion fails (#71)
        conn.request("GET", "/api/device/places?" + query)
        r = conn.getresponse()
        r.read()
        conn.close()
        return r.status

    def test_known_ids_only(self):
        self.assertEqual(self.get(f"id={PC}&minutes=60"), 200)
        self.assertEqual(self.get("id=dev:nobody&minutes=60"), 404)
        self.assertEqual(self.get("id=grp:1&minutes=60"), 404)
        self.assertEqual(self.get("id=" + "dev:" + "a" * 80), 404)
        self.assertEqual(self.get(f"id={PC}&minutes=0"), 400)


class PageTest(unittest.TestCase):
    def test_where_its_been_is_escaped_and_fetched_per_device(self):
        page = page_code()
        block = page[page.index("function placesHtml("):page.index("function renderDetail(")]
        self.assertIn("encodeURIComponent(id)", block)
        self.assertIn("esc(p.node_name", block)
        self.assertIn(".catch(failed)", block)              # a failed fetch says so, then retries
        self.assertIn("renderDetail(latestTree||tree)", block)   # a late answer uses the current map
        self.assertNotIn("renderDetail(tree)", block)
        self.assertIn("Where it's been", page)


class MeshLoopRecordsTest(unittest.TestCase):
    def test_a_failed_record_resets_a_pending_move(self):
        # move seen (pending), then a reading whose record step fails, then the move again: still
        # only one good reading of it, so nothing is recorded yet
        calls = {"n": 0}
        real = collectors.analysis.places_now

        def places_now(view):
            calls["n"] += 1
            if calls["n"] == 3:
                raise RuntimeError("the map couldn't be worked out")
            return real(view)
        with mock.patch.object(collectors.analysis, "places_now", side_effect=places_now):
            db, _, _ = run_mesh_loop(self, lambda fake: setattr(fake, "pc_unit", "20-E1-5D-5E-00-05"), readings=4)
        rows = db.execute("SELECT node FROM device_places WHERE device = 'dev:60:cf:84:5e:00:02'").fetchall()
        self.assertEqual(rows, [("20:e1:5d:5e:00:04",)])

    def test_a_failed_reading_resets_a_pending_move(self):
        # move seen (pending), then a failed reading, then the move seen again: that's one good
        # reading of it since the failure, so nothing is recorded yet
        real = {}

        def each(fake, n):
            if n == 2:                       # the next reading fails: the Deco answers nothing usable
                real["answer"] = fake.answer
                fake.answer = lambda path, body: {"error_code": -1}
            elif n == 3:
                fake.answer = real["answer"]
        db, _, _ = run_mesh_loop(self, lambda fake: setattr(fake, "pc_unit", "20-E1-5D-5E-00-05"), readings=4,
                                 each=each)
        rows = db.execute("SELECT node FROM device_places WHERE device = 'dev:60:cf:84:5e:00:02'").fetchall()
        self.assertEqual(rows, [("20:e1:5d:5e:00:04",)])   # still only the first place

    def test_a_move_is_confirmed_through_the_real_loop(self):
        # the PC moves from Office to Living Room after the first reading: the second reading makes
        # it pending, the third confirms it - only if the loop adopts the pending changes it returned
        db, _, _ = run_mesh_loop(self, lambda fake: setattr(fake, "pc_unit", "20-E1-5D-5E-00-05"), readings=3)
        rows = db.execute("SELECT node FROM device_places WHERE device = 'dev:60:cf:84:5e:00:02' ORDER BY ts").fetchall()
        self.assertEqual(rows, [("20:e1:5d:5e:00:04",), ("20:e1:5d:5e:00:05",)])

    def test_a_good_reading_records_where_listed_devices_are(self):
        db, _, _ = run_mesh_loop(self, lambda fake: None)
        rows = db.execute("SELECT device, how FROM device_places").fetchall()
        self.assertIn(("dev:60:cf:84:5e:00:02", "mesh"), rows)   # the PC the scripted mesh lists


if __name__ == "__main__":
    unittest.main()
