import base64
import hashlib
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from unittest import mock

from hearth import analysis, collectors, crypto, mesh, store
from tests.helpers import (DEVICE_LIST, LOUNGE, MAIN, OFFICE, PC, SERVER, SHIELD, FakeConn, FakeDeco, b64, mem_db, snapshot)


class ParseTest(unittest.TestCase):
    def test_nodes_and_parents(self):
        nodes = {n["mac"]: n for n in mesh.link_parents(mesh.parse_nodes(DEVICE_LIST))}
        self.assertEqual(set(nodes), {MAIN, OFFICE, LOUNGE})
        self.assertEqual(nodes[MAIN]["role"], "main")
        self.assertIsNone(nodes[MAIN]["parent"])
        self.assertEqual((nodes[OFFICE]["parent"], nodes[OFFICE]["backhaul"], nodes[OFFICE]["name"]),
                         (MAIN, "wireless", "Office"))
        self.assertEqual(nodes[OFFICE]["signal"], {"band5": 2, "band6": 3})
        self.assertEqual(nodes[LOUNGE]["backhaul"], "wired")
        self.assertNotIn("parent_id", nodes[MAIN])

    def test_clients_only_online_and_links_normalised(self):
        res = {"client_list": [
            {"mac": "60-CF-84-5E-00-02", "ip": "192.168.1.228", "online": True, "connection_type": "wired",
             "name": b64("Device_5609")},
            {"mac": "52-49-A1-5E-00-0B", "ip": "192.168.1.161", "online": True, "connection_type": "band6", "name": "Mac"},
            {"mac": "DA-68-26-5E-00-08", "online": False, "name": b64("Watch")},
            {"mac": "AA-BB-CC-DD-EE-FF", "online": True, "connection_type": "<script>"}]}
        out = mesh.parse_clients(res, OFFICE)
        self.assertEqual([(c["mac"], c["link"], c["node"]) for c in out],
                         [(PC, "wired", OFFICE), ("52:49:a1:5e:00:0b", "band6", OFFICE), ("aa:bb:cc:dd:ee:ff", "unknown", OFFICE)])
        self.assertEqual(out[0]["name"], "Device_5609")  # base64 decoded
        self.assertEqual(out[1]["name"], "Mac")          # not base64: kept as is

    def test_unexpected_shapes(self):
        for res in (None, [], {}, {"device_list": "x"}, {"client_list": None}):
            self.assertEqual(mesh.parse_nodes(res), [])
            self.assertEqual(mesh.parse_clients(res, MAIN), [])


class DecoClientTest(unittest.TestCase):
    def setUp(self):
        fd, self.pw = tempfile.mkstemp()
        with os.fdopen(fd, "w") as f:
            f.write("GLINET_PASSWORD=router-pass\nDECO_PASSWORD=s3cret-deco\n")
        self.addCleanup(os.remove, self.pw)
        FakeConn.cert = b"certificate-A"

    def run_deco(self, deco_password="s3cret-deco", pins=None):
        fake = FakeDeco(deco_password)
        pins = {} if pins is None else pins
        with mock.patch.object(mesh.http.client, "HTTPSConnection", lambda *a, **k: FakeConn(fake)):
            snap = mesh.Deco("192.168.1.231", self.pw, pins).snapshot()
        return snap, fake, pins

    def test_reads_the_mesh_and_never_sends_the_password_in_clear(self):
        fake = FakeDeco("s3cret-deco")
        pins = {}
        with mock.patch.object(mesh.http.client, "HTTPSConnection", lambda *a, **k: FakeConn(fake)):
            d = mesh.Deco("192.168.1.231", self.pw, pins)
            snap = d.snapshot()
        self.assertEqual(len(snap["nodes"]), 3)
        self.assertEqual([(c["mac"], c["node"]) for c in snap["clients"]], [(PC, OFFICE)])
        everything = b"".join(fake.sent)
        self.assertNotIn(b"s3cret-deco", everything)
        self.assertNotIn(b"router-pass", everything)
        # first contact only proposes a pin; the shared pins are untouched until the caller keeps it
        self.assertEqual(d.new_pin, hashlib.sha256(b"certificate-A").hexdigest())
        self.assertEqual(pins, {})

    def test_a_different_certificate_is_refused_before_anything_is_sent(self):
        pins = {"192.168.1.231": hashlib.sha256(b"certificate-A").hexdigest()}
        FakeConn.cert = b"certificate-B"
        fake = FakeDeco("s3cret-deco")
        with mock.patch.object(mesh.http.client, "HTTPSConnection", lambda *a, **k: FakeConn(fake)):
            with self.assertRaises(mesh.MeshTransportError) as cm:
                mesh.Deco("192.168.1.231", self.pw, pins).snapshot()
        self.assertIn("different certificate", str(cm.exception))  # the real reason, not "failed"
        self.assertEqual(fake.sent, [])

    def test_moved_unit_is_rediscovered_only_with_a_known_certificate(self):
        known = {"192.168.1.231": hashlib.sha256(b"certificate-A").hexdigest()}
        fake = FakeDeco("s3cret-deco")
        with mock.patch.object(mesh.http.client, "HTTPSConnection", lambda *a, **k: FakeConn(fake)):
            d = mesh.Deco("192.168.1.240", self.pw, known)   # same unit, new DHCP address
            d.snapshot()
        self.assertEqual(d.new_pin, known["192.168.1.231"])
        FakeConn.cert = b"stranger"
        stranger = FakeDeco("s3cret-deco")
        with mock.patch.object(mesh.http.client, "HTTPSConnection", lambda *a, **k: FakeConn(stranger)):
            with self.assertRaises(mesh.MeshTransportError) as cm:
                mesh.Deco("192.168.1.66", self.pw, known).snapshot()
        self.assertIn("doesn't know", str(cm.exception))
        self.assertEqual(stranger.sent, [])  # nothing - least of all the password - was sent

    def test_a_node_refusing_its_client_list_costs_no_extra_login(self):
        class OfflineLivingRoom(FakeDeco):
            """Living Room is offline: its client list comes back as an error."""
            logins = 0

            def answer(self, path, body):
                if path.endswith("form=login"):
                    self.logins += 1
                if "client_list" in path:
                    from urllib.parse import parse_qs
                    form = parse_qs(body.decode())
                    sign = dict(p.split("=", 1) for p in self._rsa_decrypt(form["sign"][0]).split("&"))
                    key, iv = sign["k"].encode(), sign["i"].encode()
                    req = json.loads(crypto.aes_cbc_decrypt(key, iv, base64.b64decode(form["data"][0])))
                    if req["params"]["device_mac"] == "20-E1-5D-5E-00-05":
                        return {"data": base64.b64encode(crypto.aes_cbc_encrypt(
                            key, iv, json.dumps({"error_code": -1}).encode())).decode()}
                return super().answer(path, body)

        fake = OfflineLivingRoom("s3cret-deco")
        with mock.patch.object(mesh.http.client, "HTTPSConnection", lambda *a, **k: FakeConn(fake)):
            snap = mesh.Deco("192.168.1.231", self.pw, {}).snapshot()
        self.assertEqual(fake.logins, 1)                                            # no extra login
        self.assertEqual([(c["mac"], c["node"]) for c in snap["clients"]], [(PC, OFFICE)])

    def test_refused_password_is_an_auth_error(self):
        fake = FakeDeco("the-real-one")
        with mock.patch.object(mesh.http.client, "HTTPSConnection", lambda *a, **k: FakeConn(fake)):
            with self.assertRaises(mesh.MeshAuthError):
                mesh.Deco("192.168.1.231", self.pw, {}).snapshot()

    def test_certificate_changing_mid_session_is_refused(self):
        fake = FakeDeco("s3cret-deco")
        conns = iter(range(100))

        def connect(*a, **k):
            c = FakeConn(fake)
            if next(conns) >= 3:  # after keys, auth and login, someone else answers
                c.sock.getpeercert.return_value = b"certificate-B"
            return c
        with mock.patch.object(mesh.http.client, "HTTPSConnection", connect):
            with self.assertRaises(mesh.MeshTransportError):
                mesh.Deco("192.168.1.231", self.pw, {}).snapshot()

    def test_wrong_password(self):
        fake = FakeDeco("the-real-one")
        with mock.patch.object(mesh.http.client, "HTTPSConnection", lambda *a, **k: FakeConn(fake)):
            with self.assertRaises(mesh.MeshError) as cm:
                mesh.Deco("192.168.1.231", self.pw, {}).snapshot()
        self.assertNotIn("s3cret", str(cm.exception))

    def test_only_lan_addresses(self):
        for host in ("8.8.8.8", "127.0.0.1", "deco.example"):
            with self.assertRaises((mesh.MeshError, ValueError)):
                mesh.Deco(host, self.pw, {})


class MeshAnalysisTest(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)
        snap = snapshot()
        snap["ts"] = 10**10  # recent
        store.set_state(self.c, mesh.MESH_STATE_KEY, snap)
        p = mock.patch.object(analysis, "_my_ip", return_value="192.168.1.60")
        p.start()
        self.addCleanup(p.stop)
        analysis.clear_cache()  # mesh_index is cached; each test sets its own mesh
        self.addCleanup(analysis.clear_cache)

    def test_route_from_the_mesh(self):
        idx = analysis.mesh_index(self.c)
        self.assertEqual(analysis.path_label(None, {}, {}, idx), "Via Office → wireless → Bedroom → router")

    def test_groups_named_after_their_mesh_node(self):
        idx = analysis.mesh_index(self.c)
        snap = {"local": {"group": 1, "members": ["dev:" + PC, "dev:" + OFFICE]},
                "branches": [{"group": 2, "members": ["dev:" + SHIELD]}], "relays": [], "roles": {}}
        ch = analysis.chain(snap, {"gateway"}, {}, {}, idx)
        self.assertEqual(ch[0]["link"], "Office mesh node or its wireless link to Bedroom")
        self.assertEqual(ch[0]["name"], "Office (this computer's mesh node)")
        self.assertEqual(analysis.branches_of(snap, {}, {}, idx)[0]["name"], "Branch via Living Room")
        # your own name for a group still wins
        self.assertEqual(analysis.chain(snap, set(), {"grp:1": "Study"}, {}, idx)[0]["name"], "Study")

    def test_old_reading_is_ignored(self):
        old = snapshot()
        store.set_state(self.c, mesh.MESH_STATE_KEY, old)  # ts 0: ancient
        analysis.clear_cache()  # as the mesh reader does after every new reading
        self.assertIsNone(analysis.mesh_index(self.c))

    def test_matching_by_mac_first(self):
        # an old row for another device that used to have the PC's address, and the Deco node
        # seen by Hearth under a different MAC than the mesh lists
        self.c.executemany("INSERT INTO devices (ip, mac, online) VALUES (?,?,0)", [
            ("192.168.1.228", "aa:aa:aa:aa:aa:01"),
            ("192.168.1.231", "02:00:00:00:00:31")])
        analysis.clear_cache()
        where = analysis.mesh_index(self.c)["where"]
        self.assertNotIn("dev:aa:aa:aa:aa:aa:01", where)          # stale row: not given the PC's place
        self.assertEqual(where["dev:02:00:00:00:00:31"], MAIN)     # node by its address: fine
        self.assertEqual(where["dev:" + PC], OFFICE)

    def test_old_reading_is_not_drawn_as_current(self):
        store.set_state(self.c, mesh.MESH_STATE_KEY, snapshot())  # ts 0
        v = analysis.mesh_view(self.c)
        self.assertFalse(v["available"])
        self.assertEqual(v["stale_since"], 0)

    def test_view(self):
        v = analysis.mesh_view(self.c)
        self.assertTrue(v["available"])
        self.assertEqual(v["self"], "dev:" + SERVER)
        self.assertEqual({d["node"] for d in v["devices"]}, {OFFICE, LOUNGE})


class MeshChangesTest(unittest.TestCase):
    def test_events_for_drop_off_return_and_backhaul_change(self):
        old = snapshot()
        new = json.loads(json.dumps(old))
        office = next(n for n in new["nodes"] if n["mac"] == OFFICE)
        office["backhaul"] = "wired"
        lounge = next(n for n in new["nodes"] if n["mac"] == LOUNGE)
        lounge["online"] = False
        self.assertEqual(sorted(collectors.mesh_changes(old, new)),
                         ["Mesh node Living Room dropped off the mesh", "Mesh node Office now connects wired (was wireless)"])
        self.assertEqual(collectors.mesh_changes(None, new), [])
        self.assertEqual(sorted(collectors.mesh_changes(new, old)), ["Mesh node Living Room is back on the mesh",
                                                             "Mesh node Office now connects wireless (was wired)"])


class CandidatesTest(unittest.TestCase):
    VENDORS = {"20:e1:5d": "TP-Link Systems Inc.", "48:b0:2d": "NVIDIA", "aa:bb:cc": "Acme"}

    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)
        self.c.executemany("INSERT INTO devices (ip, mac, name, online) VALUES (?,?,?,1)", [
            ("192.168.1.163", "20:e1:5d:5e:00:05", "deco-BE9300.lan"),
            ("192.168.1.231", "20-E1-5D-5E-00-03", None),
            ("192.168.1.66", "aa:bb:cc:00:00:01", "deco-totally-real.lan"),   # names itself "deco"
            ("192.168.1.137", SHIELD, "SHIELD")])
        self.vendor = lambda mac: self.VENDORS.get(mac[:8])

    def test_first_setup_trusts_the_mac_maker_never_the_name(self):
        self.assertEqual(mesh.find_candidates(self.c, {}, self.vendor), ["192.168.1.163", "192.168.1.231"])

    def test_after_setup_pinned_hosts_first_then_tplink_devices(self):
        store.set_state(self.c, "mesh_host", "192.168.1.231")
        pins = {"192.168.1.163": "x", "192.168.1.231": "y", "192.168.1.200": "z"}
        # unpinned TP-Link devices stay as fall-backs; the client will demand a known certificate
        self.assertEqual(mesh.find_candidates(self.c, pins, self.vendor),
                         ["192.168.1.231", "192.168.1.163", "192.168.1.200"])

    def test_configured_host_wins(self):
        with mock.patch.dict(mesh.CFG, {"mesh_host": "192.168.1.231"}):
            self.assertEqual(mesh.find_candidates(self.c, {"192.168.1.163": "x"}, self.vendor), ["192.168.1.231"])


class MeshLoopTest(unittest.TestCase):
    def test_bad_reading_backs_off_and_pin_kept_only_after_success(self):
        logs, stop, calls = [], threading.Event(), {"n": 0}
        db = mem_db()
        self.addCleanup(db.close)
        db.execute("INSERT INTO devices (ip, mac, online) VALUES ('192.168.1.231', '20:e1:5d:5e:00:03', 1)")

        class FakeMeshDeco:
            def __init__(self, host, path, pins, identity=None):
                self.keys = None
                self.host, self.pin, self.new_pin = host, pins.get(host), "proposed-pin"

            def snapshot(self):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise sqlite3.OperationalError("database is locked")  # not a MeshError
                stop.set()
                return snapshot()

        fd, pw = tempfile.mkstemp()
        with os.fdopen(fd, "w") as f:
            f.write("DECO_PASSWORD=x\n")
        self.addCleanup(os.remove, pw)
        with mock.patch.object(collectors, "store", wraps=store) as st, \
                mock.patch.object(collectors.mesh, "Deco", FakeMeshDeco), \
                mock.patch.object(collectors.router, "credentials_path", return_value=pw), \
                mock.patch.object(collectors.net, "vendor", return_value="TP-Link Systems Inc."), \
                mock.patch.object(collectors, "log", side_effect=lambda *a: logs.append(" ".join(map(str, a)))), \
                mock.patch.multiple(collectors, ROUTER_MIN_REFRESH_GAP_S=0, ROUTER_RETRY_S=0.01):
            st.db.return_value = db
            collectors.mesh_loop(stop)
        self.assertEqual(calls["n"], 2)                                     # survived, retried
        self.assertEqual(db.execute("SELECT COUNT(*) FROM mesh_links").fetchone()[0], 3)  # first reading: all nodes
        self.assertEqual(sum("can't read the mesh" in m for m in logs), 1)  # logged once
        self.assertEqual(store.get_state(db, mesh.PINS_STATE_KEY), {"192.168.1.231": "proposed-pin"})
        self.assertIsNone(store.get_state(db, mesh.MESH_ERROR_KEY))


class MeshAuthBackoffTest(unittest.TestCase):
    def test_wrong_password_stops_at_the_first_host_and_keeps_the_long_backoff(self):
        stop, tried, logs = threading.Event(), [], []
        db = mem_db()
        self.addCleanup(db.close)

        class Refused:
            def __init__(self, host, path, pins, identity=None):
                self.keys = None
                self.host = host

            def snapshot(self):
                tried.append(self.host)
                raise mesh.MeshAuthError("login refused (error -5002; check DECO_PASSWORD)")

        fd, pw = tempfile.mkstemp()
        with os.fdopen(fd, "w") as f:
            f.write("DECO_PASSWORD=x\n")
        self.addCleanup(os.remove, pw)
        backoffs = []

        def fake_backoff(stop_, event, timeout, **kw):  # the failure back-off wait: record it, then stop
            backoffs.append(timeout)
            stop.set()
            return "stop"
        with mock.patch.object(collectors, "store", wraps=store) as st, \
                mock.patch.object(collectors.mesh, "Deco", Refused), \
                mock.patch.object(collectors.mesh, "find_candidates", return_value=["192.168.1.231", "192.168.1.163"]), \
                mock.patch.object(collectors.router, "credentials_path", return_value=pw), \
                mock.patch.object(collectors, "log", side_effect=lambda *a: logs.append(" ".join(map(str, a)))), \
                mock.patch.object(collectors, "wait_either", side_effect=fake_backoff), \
                mock.patch.multiple(collectors, ROUTER_MIN_REFRESH_GAP_S=0):
            st.db.return_value = db
            collectors.mesh_loop(stop)
        self.assertEqual(tried, ["192.168.1.231"])                        # one failed login, not two
        self.assertEqual(backoffs, [collectors.MESH_AUTH_RETRY_S])        # the long back-off
        self.assertIn("login refused", store.get_state(db, mesh.MESH_ERROR_KEY)["error"])


class MeshLinksHistoryTest(unittest.TestCase):
    def test_only_changes_are_recorded(self):
        stop, readings = threading.Event(), []
        db = mem_db()
        self.addCleanup(db.close)
        first = snapshot()
        changed = json.loads(json.dumps(first))
        next(n for n in changed["nodes"] if n["mac"] == OFFICE)["signal"] = {"band5": 1, "band6": 3}
        script = [first, json.loads(json.dumps(first)), changed]

        class Scripted:
            def __init__(self, host, path, pins, identity=None):
                self.keys = None
                self.host, self.pin, self.new_pin = host, "p", None

            def snapshot(self):
                readings.append(1)
                if len(readings) == len(script):
                    stop.set()
                return script[len(readings) - 1]

        fd, pw = tempfile.mkstemp()
        with os.fdopen(fd, "w") as f:
            f.write("DECO_PASSWORD=x\n")
        self.addCleanup(os.remove, pw)
        with mock.patch.object(collectors, "store", wraps=store) as st, \
                mock.patch.object(collectors.mesh, "Deco", Scripted), \
                mock.patch.object(collectors.mesh, "find_candidates", return_value=["192.168.1.231"]), \
                mock.patch.object(collectors.mesh, "poll_interval_s", return_value=0), \
                mock.patch.object(collectors.router, "credentials_path", return_value=pw), \
                mock.patch.object(collectors, "log"), \
                mock.patch.multiple(collectors, ROUTER_MIN_REFRESH_GAP_S=0):
            st.db.return_value = db
            collectors.mesh_loop(stop)
        rows = db.execute("SELECT mac FROM mesh_links ORDER BY ts").fetchall()
        self.assertEqual(len(rows), 4)          # 3 nodes at first, then only Office's signal change
        self.assertEqual(rows[-1][0], OFFICE)


class WaitEitherTest(unittest.TestCase):
    def test_outcomes(self):
        stop, ev = threading.Event(), threading.Event()
        self.assertIsNone(collectors.wait_either(stop, ev, 0.05, step=0.01))
        ev.set()
        self.assertEqual(collectors.wait_either(stop, ev, 5), "refresh")
        stop.set()
        self.assertEqual(collectors.wait_either(stop, threading.Event(), 60), "stop")


class MeshNamingTest(unittest.TestCase):
    def test_mesh_app_names_win_over_hostnames_placeholders_skipped(self):
        from hearth.naming import device_names
        c = mem_db()
        self.addCleanup(c.close)
        snap = snapshot()
        snap["clients"].append({"mac": "fa:6b:bd:5e:00:09", "ip": "192.168.1.134", "node": MAIN,
                                "link": "band6", "name": "phone_1DA3"})
        snap["clients"][0]["name"] = "Device_98A4"
        store.set_state(c, mesh.MESH_STATE_KEY, snap)
        c.executemany("INSERT INTO devices (ip, mac, name, vendor, online) VALUES (?,?,?,?,1)", [
            ("192.168.1.231", "02:00:00:00:00:31", "deco-BE9300.lan", None),       # node, by IP
            ("192.168.1.134", "fa:6b:bd:5e:00:09", None, "Private address (phone/laptop)"),
            ("192.168.1.60", SERVER, "HomeServer.lan", None)])
        names = device_names(c)
        self.assertEqual(names["dev:02:00:00:00:00:31"], "Bedroom")
        self.assertEqual(names["dev:fa:6b:bd:5e:00:09"], "phone_1DA3")
        self.assertEqual(names["dev:" + SERVER], "HomeServer.lan")      # placeholder not used


if __name__ == "__main__":
    unittest.main()
