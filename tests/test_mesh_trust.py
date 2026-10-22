import hashlib
import http.client
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

from hearth import collectors, mesh, store
from hearth.web import Handler
from tests.helpers import HOST, MAIN, FakeConn, FakeDeco, mem_db, run_mesh_loop, snapshot

OLD = hashlib.sha256(b"certificate-A").hexdigest()
NEW = hashlib.sha256(b"certificate-B").hexdigest()


class CertChangeTest(unittest.TestCase):
    def setUp(self):
        fd, self.pw = tempfile.mkstemp()
        with os.fdopen(fd, "w") as f:
            f.write("DECO_PASSWORD=s3cret\n")
        self.addCleanup(os.remove, self.pw)
        FakeConn.cert = b"certificate-B"
        self.addCleanup(setattr, FakeConn, "cert", b"certificate-A")

    def test_changed_certificate_names_both_and_sends_nothing(self):
        fake = FakeDeco("s3cret")
        with mock.patch.object(mesh.http.client, "HTTPSConnection", lambda *a, **k: FakeConn(fake)):
            with self.assertRaises(mesh.CertChanged) as cm:
                mesh.Deco(HOST, self.pw, {HOST: OLD}).snapshot()
        self.assertEqual((cm.exception.host, cm.exception.old, cm.exception.new), (HOST, OLD, NEW))
        self.assertEqual(fake.sent, [])


def db_with_pending():
    c = mem_db()
    snap = snapshot()
    snap["ts"] = 10 ** 10
    store.set_state(c, mesh.MESH_STATE_KEY, snap)
    store.set_state(c, "mesh_host", HOST)
    store.set_state(c, mesh.PINS_STATE_KEY, {HOST: OLD})
    c.execute("INSERT INTO devices (ip, mac, online) VALUES (?,?,1)", (HOST, MAIN.upper().replace(":", "-")))
    collectors.note_cert_change(c, mesh.CertChanged(HOST, OLD, NEW))
    return c


class PendingTest(unittest.TestCase):
    def test_recorded_once_for_the_main_unit_only(self):
        c = db_with_pending()
        self.addCleanup(c.close)
        p = mesh.pending_cert(c)
        self.assertEqual((p["host"], p["old"], p["new"], p["name"]), (HOST, OLD, NEW, "Bedroom"))
        self.assertTrue(p["same_device"])  # the MAC at that address is still the main unit's
        collectors.note_cert_change(c, mesh.CertChanged(HOST, OLD, NEW))
        self.assertEqual(c.execute("SELECT COUNT(*) FROM events WHERE kind = 'mesh'").fetchone()[0], 1)
        collectors.note_cert_change(c, mesh.CertChanged("192.168.1.237", "a" * 64, "b" * 64))  # a satellite
        self.assertEqual(mesh.pending_cert(c)["host"], HOST)

    def test_already_trusted_is_not_reopened(self):
        c = db_with_pending()
        self.addCleanup(c.close)
        self.assertTrue(mesh.trust(c, HOST, NEW))
        mesh.TRUSTED.clear()
        # a reading that started before the click reports the change afterwards
        collectors.note_cert_change(c, mesh.CertChanged(HOST, OLD, NEW))
        self.assertIsNone(mesh.pending_cert(c))

    def test_flipping_certificates_log_once_per_period(self):
        c = db_with_pending()
        self.addCleanup(c.close)
        for i in range(10):
            collectors.note_cert_change(c, mesh.CertChanged(HOST, OLD, f"{i:064x}"))
        self.assertEqual(c.execute("SELECT COUNT(*) FROM events WHERE kind = 'mesh'").fetchone()[0], 1)
        self.assertEqual(mesh.pending_cert(c)["new"], f"{9:064x}")  # the banner shows the latest

    def test_different_mac_is_flagged(self):
        c = db_with_pending()
        self.addCleanup(c.close)
        c.execute("UPDATE devices SET mac = 'aa:bb:cc:dd:ee:ff' WHERE ip = ?", (HOST,))
        p = mesh.pending_cert(c)
        self.assertFalse(p["same_device"])
        self.assertEqual(p["mac_now"], "aa:bb:cc:dd:ee:ff")

    def test_trust_only_the_exact_pending_certificate(self):
        c = db_with_pending()
        self.addCleanup(c.close)
        mesh.TRUSTED.clear()
        self.addCleanup(mesh.TRUSTED.clear)
        self.assertFalse(mesh.trust(c, HOST, "c" * 64))            # not what's pending
        self.assertFalse(mesh.trust(c, "192.168.1.237", NEW))      # not that host
        self.assertEqual(store.get_state(c, mesh.PINS_STATE_KEY), {HOST: OLD})
        self.assertTrue(mesh.trust(c, HOST, NEW))
        self.assertEqual(store.get_state(c, mesh.PINS_STATE_KEY), {HOST: NEW})
        self.assertIsNone(mesh.pending_cert(c))
        self.assertTrue(mesh.TRUSTED.is_set())                     # the reader tries again at once


FAKE_KEY = [format(FakeDeco("x").n, "x"), "10001"]           # FakeDeco offers this for both keys
KEYS = {"password": mesh.key_fingerprint(FAKE_KEY), "sign": mesh.key_fingerprint(FAKE_KEY)}
OTHER = "c" * 64


def identity(**over):
    return {"host": HOST, **KEYS, "mac": MAIN, "since": 1.0, **over}


class TrustState(unittest.TestCase):
    """A database where the main unit is pinned and its identity recorded."""

    def fresh(self, ident=None):
        c = mem_db()
        self.addCleanup(c.close)
        snap = snapshot()
        snap["ts"] = 10 ** 10
        store.set_state(c, mesh.MESH_STATE_KEY, snap)
        store.set_state(c, "mesh_host", HOST)
        store.set_state(c, mesh.PINS_STATE_KEY, {HOST: OLD})
        store.set_state(c, mesh.IDENTITY_STATE_KEY, ident or identity())
        c.commit()
        mesh.TRUSTED.clear()
        self.addCleanup(mesh.TRUSTED.clear)
        return c

    def events(self, c):
        return [r[0] for r in c.execute("SELECT detail FROM events WHERE kind = 'mesh' ORDER BY ts")]


class AutoTrustTest(TrustState):
    def test_same_keys_and_mac_are_accepted_and_logged(self):
        c = self.fresh()
        # the ARP table may write it upper-case with dashes: still the same MAC
        collectors.note_cert_change(c, mesh.CertChanged(HOST, OLD, NEW), MAIN.upper().replace(":", "-"), MAIN, KEYS)
        self.assertEqual(store.get_state(c, mesh.PINS_STATE_KEY), {HOST: NEW})
        self.assertIsNone(mesh.pending_cert(c))
        self.assertTrue(mesh.TRUSTED.is_set())  # reads again straight away
        self.assertIn("login keys and MAC", self.events(c)[0])

    def test_no_daily_cap_and_one_event_a_day(self):
        c = self.fresh()
        old = OLD
        for i in range(10):                     # a unit changing certificate all day long
            new = f"{i:064x}"
            collectors.note_cert_change(c, mesh.CertChanged(HOST, old, new), MAIN, MAIN, KEYS)
            self.assertEqual(store.get_state(c, mesh.PINS_STATE_KEY)[HOST], new)
            old = new
        self.assertEqual(len(self.events(c)), 1)
        self.assertEqual(store.get_state(c, mesh.CERT_LOG_KEY)["count"], 10)
        store.set_state(c, mesh.CERT_LOG_KEY, {"day": "2026-01-01", "count": 10})   # as if yesterday
        collectors.note_cert_change(c, mesh.CertChanged(HOST, old, NEW), MAIN, MAIN, KEYS)
        self.assertIn("It changed 10 times on 2026-01-01", self.events(c)[-1])
        self.assertEqual(store.get_state(c, mesh.CERT_LOG_KEY)["count"], 1)

    def test_damaged_daily_log_only_costs_an_extra_event(self):
        for damaged in ("{not json", '{"count": "x"}', '{"count": -1}', '[1]', '{"count": true}'):
            c = self.fresh()
            c.execute("INSERT OR REPLACE INTO state VALUES (?, ?)", (mesh.CERT_LOG_KEY, damaged))
            collectors.note_cert_change(c, mesh.CertChanged(HOST, OLD, NEW), MAIN, MAIN, KEYS)
            self.assertEqual(store.get_state(c, mesh.PINS_STATE_KEY), {HOST: NEW}, damaged)
            self.assertEqual(store.get_state(c, mesh.CERT_LOG_KEY)["count"], 1, damaged)

    def test_anything_else_waits_for_you_with_the_reason(self):
        cases = [  # (identity, keys, before, after, words in the reason)
            (None, KEYS, MAIN, MAIN, "hasn't recorded this unit's login keys"),
            (identity(), None, MAIN, MAIN, "couldn't be read"),
            (identity(), {**KEYS, "sign": OTHER}, MAIN, MAIN, "signing key changed"),
            (identity(), {"password": OTHER, "sign": OTHER}, MAIN, MAIN, "password-encryption and signing key"),
            (identity(mac=None), KEYS, MAIN, MAIN, "MAC hasn't been recorded"),
            (identity(), KEYS, None, MAIN, "wasn't in this computer's ARP table before"),
            (identity(), KEYS, MAIN, None, "wasn't in this computer's ARP table after"),
            (identity(), KEYS, "aa:bb:cc:dd:ee:ff", MAIN, "belonged to MAC aa:bb:cc:dd:ee:ff before"),
            (identity(), KEYS, MAIN, "aa:bb:cc:dd:ee:ff", "belonged to MAC aa:bb:cc:dd:ee:ff after"),
        ]
        for ident, keys, before, after, why in cases:
            c = self.fresh()
            if ident is None:
                store.set_state(c, mesh.IDENTITY_STATE_KEY, None)
            else:
                store.set_state(c, mesh.IDENTITY_STATE_KEY, ident)
            collectors.note_cert_change(c, mesh.CertChanged(HOST, OLD, NEW), before, after, keys)
            self.assertEqual(store.get_state(c, mesh.PINS_STATE_KEY), {HOST: OLD}, why)
            p = mesh.pending_cert(c)
            new_keys = bool(ident and keys and keys != KEYS)  # new keys with the new certificate
            self.assertEqual((p["new"], p["kind"]), (NEW, "keys" if new_keys else "cert"), why)
            self.assertIn(why, p["reason"])
            # the event says why, or - for new keys - that it's the login keys
            self.assertIn("login keys" if new_keys else why, self.events(c)[0])
            self.assertFalse(mesh.TRUSTED.is_set())

    def test_setting_off_always_asks(self):
        c = self.fresh()
        for off in (False, "false", "off"):
            with mock.patch.dict(mesh.CFG, {"mesh_auto_trust": off}):
                collectors.note_cert_change(c, mesh.CertChanged(HOST, OLD, NEW), MAIN, MAIN, KEYS)
            self.assertEqual(store.get_state(c, mesh.PINS_STATE_KEY), {HOST: OLD}, off)
            self.assertIn("mesh_auto_trust", mesh.pending_cert(c)["reason"])

    def test_event_rate_limit_survives_a_good_reading(self):
        c = self.fresh()
        collectors.note_cert_change(c, mesh.CertChanged(HOST, OLD, NEW), None, None, KEYS)
        store.set_state(c, mesh.CERT_PENDING_KEY, None)    # a good reading clears the banner...
        collectors.note_cert_change(c, mesh.CertChanged(HOST, OLD, OTHER), None, None, KEYS)
        self.assertEqual(len(self.events(c)), 1)          # ...but not the once-per-period limit
        self.assertEqual(mesh.pending_cert(c)["new"], OTHER)

    def test_damaged_pins_or_identity_are_a_failed_write_not_a_crash(self):
        for key, bad in ((mesh.PINS_STATE_KEY, ("{not json", '"text"')),
                         (mesh.IDENTITY_STATE_KEY, ("{not json", '"text"', '{"host": 1}',
                                                    json.dumps(identity(sign="short")),
                                                    json.dumps(identity(mac="not-a-mac"))))):
            for damaged in bad:
                c = self.fresh()
                c.execute("INSERT OR REPLACE INTO state VALUES (?, ?)", (key, damaged))
                c.commit()
                with mock.patch.object(collectors, "log") as lg:
                    collectors.note_cert_change(c, mesh.CertChanged(HOST, OLD, NEW), MAIN, MAIN, KEYS)
                    if key == mesh.IDENTITY_STATE_KEY:   # a keys change doesn't touch the pins
                        collectors.note_keys_change(c, mesh.KeysChanged(HOST, KEYS, {**KEYS, "sign": OTHER}, OLD))
                self.assertIn("delete the state row", lg.call_args[0][0], (key, damaged))
                self.assertIsNone(store.get_state(c, mesh.CERT_PENDING_KEY), (key, damaged))
                self.assertFalse(c.in_transaction)

    def test_unreadable_arp_table_means_ask(self):
        with mock.patch.object(collectors.net, "read_arp", side_effect=OSError("no arp")):
            self.assertEqual(collectors.safe_arp(), {})


class ReviewFixesTest(TrustState):
    """From the #63 review."""

    def test_new_certificate_with_new_keys_is_a_keys_change_and_trusting_records_them(self):
        c = self.fresh()
        new_keys = {**KEYS, "sign": OTHER}
        collectors.note_cert_change(c, mesh.CertChanged(HOST, OLD, NEW), MAIN, MAIN, new_keys)
        p = mesh.pending_cert(c)
        self.assertEqual((p["kind"], p["old"], p["new"]), ("keys", OLD, NEW))
        self.assertTrue(mesh.trust(c, HOST, NEW))
        self.assertEqual(mesh.read_identity(c)["sign"], OTHER)
        self.assertEqual(store.get_state(c, mesh.PINS_STATE_KEY), {HOST: NEW})

    def test_a_certificate_change_never_records_keys(self):
        c = self.fresh()
        store.set_state(c, mesh.CERT_PENDING_KEY, {"host": HOST, "old": OLD, "new": NEW, "since": 1.0,
                                                   "kind": "cert", "reason": "x",
                                                   "keys": {**KEYS, "sign": OTHER}})
        self.assertTrue(mesh.trust(c, HOST, NEW))
        self.assertEqual(mesh.read_identity(c)["sign"], KEYS["sign"])

    def test_trust_on_a_busy_database_raises_cleanly(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.addCleanup(os.remove, path)
        src = self.fresh()
        collectors.note_cert_change(src, mesh.CertChanged(HOST, OLD, NEW), None, None, KEYS)
        src.commit()
        dst = sqlite3.connect(path)
        src.backup(dst)
        dst.close()
        a, b = sqlite3.connect(path, timeout=0.1), sqlite3.connect(path, timeout=0.1)
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        b.execute("BEGIN IMMEDIATE")                       # someone else is writing
        with self.assertRaises(sqlite3.OperationalError):   # the endpoint answers 503 "busy"
            mesh.trust(a, HOST, NEW)
        self.assertFalse(a.in_transaction)
        b.rollback()
        self.assertTrue(mesh.trust(a, HOST, NEW))           # pressed again: fine

    def test_keys_change_without_a_certificate_records_nothing(self):
        c = self.fresh()
        collectors.note_keys_change(c, mesh.KeysChanged(HOST, KEYS, {**KEYS, "sign": OTHER}, None))
        self.assertIsNone(mesh.pending_cert(c))

    def test_failed_rollback_is_still_a_failed_write(self):
        conn = mock.Mock(in_transaction=False)
        conn.execute.side_effect = sqlite3.OperationalError("disk I/O error")
        conn.rollback.side_effect = sqlite3.ProgrammingError("closed")
        with mock.patch.object(collectors, "log"):
            self.assertFalse(collectors.mesh_write(conn, lambda: None))


class LoginKeysTest(unittest.TestCase):
    """The Deco client: the main unit's identity is its two login keys."""

    def setUp(self):
        fd, self.pw = tempfile.mkstemp()
        with os.fdopen(fd, "w") as f:
            f.write("DECO_PASSWORD=s3cret\n")
        self.addCleanup(os.remove, self.pw)
        FakeConn.cert = b"certificate-A"

    def deco(self, fake, ident):
        return mock.patch.object(mesh.http.client, "HTTPSConnection", lambda *a, **k: FakeConn(fake)), \
            mesh.Deco(HOST, self.pw, {HOST: OLD}, ident)

    def test_fingerprint_ignores_case_and_leading_zeros(self):
        self.assertEqual(mesh.key_fingerprint(["00ABcd", "010001"]), mesh.key_fingerprint(["abcd", "10001"]))
        self.assertNotEqual(mesh.key_fingerprint(["abcd", "10001"]), mesh.key_fingerprint(["abce", "10001"]))

    def test_recorded_keys_log_in_and_are_reported(self):
        fake = FakeDeco("s3cret")
        patch, d = self.deco(fake, identity())
        with patch:
            d.snapshot()
        self.assertEqual(d.keys, KEYS)

    def test_other_keys_are_refused_before_the_password_is_read(self):
        fake = FakeDeco("s3cret")
        patch, d = self.deco(fake, identity(sign=OTHER))
        with patch, mock.patch.object(mesh, "read_password") as rp:
            with self.assertRaises(mesh.KeysChanged) as cm:
                d.snapshot()
        rp.assert_not_called()                                   # never even read from the file
        self.assertEqual(len(fake.sent), 2)                      # only the two public-key requests
        self.assertNotIn(b"login", b"".join(fake.sent))
        e = cm.exception
        self.assertEqual((e.host, e.old["sign"], e.new, e.cert), (HOST, OTHER, KEYS, OLD))
        self.assertIn("signing key", str(e))
        self.assertIsInstance(e, mesh.MeshTransportError)        # not retried, not a password error

    def test_read_keys_sends_nothing_secret(self):
        fake = FakeDeco("s3cret")
        patch, d = self.deco(fake, None)
        with patch:
            self.assertEqual(d.read_keys(), KEYS)
        self.assertEqual(len(fake.sent), 2)
        self.assertNotIn(b"s3cret", b"".join(fake.sent))

    def test_probe_must_see_the_new_certificate_again(self):
        FakeConn.cert = b"certificate-B"
        fake = FakeDeco("s3cret")
        with mock.patch.object(mesh.http.client, "HTTPSConnection", lambda *a, **k: FakeConn(fake)):
            self.assertEqual(collectors.probe_keys(HOST, NEW, self.pw), KEYS)
            self.assertIsNone(collectors.probe_keys(HOST, OTHER, self.pw))   # yet another certificate
        down = FakeConn(fake)
        down.connect = mock.Mock(side_effect=OSError("unreachable"))
        with mock.patch.object(mesh.http.client, "HTTPSConnection", lambda *a, **k: down):
            self.assertIsNone(collectors.probe_keys(HOST, NEW, self.pw))


class CertDecisionTest(unittest.TestCase):
    def test_accepts_only_when_everything_matches(self):
        self.assertEqual(mesh.cert_decision(identity(), KEYS, MAIN, MAIN, True), ("accept", None))
        self.assertEqual(mesh.cert_decision(identity(), KEYS, MAIN, MAIN, False)[0], "ask")
        self.assertEqual(mesh.cert_decision(identity(), {}, MAIN, MAIN, True)[0], "ask")


class KeysChangeTest(TrustState):
    def test_new_keys_wait_for_you_and_trusting_records_them(self):
        c = self.fresh()
        new_keys = {**KEYS, "password": OTHER}
        collectors.note_keys_change(c, mesh.KeysChanged(HOST, KEYS, new_keys, OLD))
        p = mesh.pending_cert(c)
        self.assertEqual((p["kind"], p["old"], p["new"]), ("keys", OLD, OLD))
        self.assertIn("login keys", self.events(c)[0])
        collectors.note_keys_change(c, mesh.KeysChanged(HOST, KEYS, new_keys, OLD))
        self.assertEqual(len(self.events(c)), 1)                 # already waiting: no second entry
        self.assertTrue(mesh.trust(c, HOST, OLD))
        ident = mesh.read_identity(c)
        self.assertEqual((ident["password"], ident["sign"], ident["mac"]), (OTHER, KEYS["sign"], None))
        self.assertIn("login keys", self.events(c)[-1])
        self.assertIsNone(mesh.pending_cert(c))

    def test_a_satellite_or_already_trusted_keys_change_nothing(self):
        c = self.fresh()
        collectors.note_keys_change(c, mesh.KeysChanged("192.168.1.237", KEYS, {**KEYS, "sign": OTHER}, OLD))
        collectors.note_keys_change(c, mesh.KeysChanged(HOST, {**KEYS, "sign": OTHER}, KEYS, OLD))
        self.assertIsNone(mesh.pending_cert(c))

    def test_trusting_a_certificate_keeps_the_keys_and_reanchors_the_mac(self):
        c = self.fresh()
        collectors.note_cert_change(c, mesh.CertChanged(HOST, OLD, NEW), "aa:bb:cc:dd:ee:ff", MAIN, KEYS)
        self.assertTrue(mesh.trust(c, HOST, NEW))
        ident = mesh.read_identity(c)
        self.assertEqual({k: ident[k] for k in KEYS}, KEYS)
        self.assertIsNone(ident["mac"])                          # recorded afresh at the next reading
        self.assertEqual(store.get_state(c, mesh.PINS_STATE_KEY), {HOST: NEW})

    def test_trust_after_unreadable_keys_keeps_the_recorded_ones(self):
        c = self.fresh()
        collectors.note_cert_change(c, mesh.CertChanged(HOST, OLD, NEW), MAIN, MAIN, None)
        self.assertTrue(mesh.trust(c, HOST, NEW))
        self.assertEqual({k: mesh.read_identity(c)[k] for k in KEYS}, KEYS)


class RememberIdentityTest(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)

    def deco(self, host=HOST, keys=KEYS):
        return mock.Mock(host=host, keys=dict(keys) if keys else None)

    def remember(self, deco, pins, anchor=MAIN):
        collectors.remember_identity(self.c, deco, pins, anchor, 5.0)
        return mesh.read_identity(self.c)

    def test_first_reading_records_keys_and_mac(self):
        self.assertEqual(self.remember(self.deco(), {}), identity(since=5.0))

    def test_no_keys_no_record(self):
        self.assertIsNone(self.remember(self.deco(keys=None), {}))

    def test_missing_mac_is_filled_but_a_recorded_one_never_replaced(self):
        store.set_state(self.c, mesh.IDENTITY_STATE_KEY, identity(mac=None))
        self.assertEqual(self.remember(self.deco(), {}, anchor=None)["mac"], None)   # no ARP entry yet
        self.assertEqual(self.remember(self.deco(), {})["mac"], MAIN)
        self.assertEqual(self.remember(self.deco(), {}, anchor="aa:bb:cc:dd:ee:ff")["mac"], MAIN)

    def test_moved_unit_drops_its_old_address(self):
        store.set_state(self.c, mesh.IDENTITY_STATE_KEY, identity())
        pins = {HOST: OLD, "192.168.1.240": OLD}
        self.assertEqual(self.remember(self.deco(host="192.168.1.240"), pins)["host"], "192.168.1.240")
        self.assertEqual(pins, {"192.168.1.240": OLD})

    def test_keys_you_confirmed_meanwhile_stand(self):
        store.set_state(self.c, mesh.IDENTITY_STATE_KEY, identity(sign=OTHER, mac=None))
        self.assertEqual(self.remember(self.deco(), {})["sign"], OTHER)


class MeshLoopIdentityTest(unittest.TestCase):
    """mesh_loop with the real client against the scripted Deco."""

    def run_loop(self, change):
        db, waits, self.arp = run_mesh_loop(self, change)
        return db, waits

    def test_first_reading_records_identity_then_a_new_certificate_is_accepted(self):
        db, waits = self.run_loop(lambda fake: setattr(FakeConn, "cert", b"certificate-B"))
        self.assertEqual(mesh.read_identity(db)["mac"], MAIN)
        self.assertEqual({k: mesh.read_identity(db)[k] for k in KEYS}, KEYS)
        self.assertEqual(store.get_state(db, mesh.PINS_STATE_KEY), {HOST: NEW})
        self.assertIsNone(mesh.pending_cert(db))
        self.assertIs(waits[-1], mesh.TRUSTED)          # accepted: read again straight away

    def test_one_arp_read_per_reading(self):
        self.run_loop(lambda fake: None)                 # two good readings, nothing changes
        self.assertEqual(self.arp.call_count, 2)         # the read before each attempt, reused

    def test_new_keys_with_the_same_certificate_wait_and_nothing_secret_is_sent(self):
        sent_after = []

        def new_keys(fake):
            # a reset unit: new key pair (only ever fingerprinted here) and the old session gone
            fake.n += 2
            real = fake.answer

            def answer(path, body):
                sent_after.append(path)
                if "stok=abc123" in path:
                    return {"error_code": -1}             # session expired: Hearth logs in again
                return real(path, body)
            fake.answer = answer
        db, _ = self.run_loop(new_keys)
        p = mesh.pending_cert(db)
        self.assertEqual((p["kind"], p["old"], p["new"]), ("keys", OLD, OLD))
        self.assertEqual(store.get_state(db, mesh.PINS_STATE_KEY), {HOST: OLD})
        self.assertEqual({k: mesh.read_identity(db)[k] for k in KEYS}, KEYS)   # the recorded keys stand
        # after the change: the expired call, then only the two public-key reads - no login
        self.assertEqual([s.split("/")[-1] for s in sent_after][1:], ["login?form=keys", "login?form=auth"])


class MeshWriteTest(unittest.TestCase):
    def test_holds_the_write_lock_from_the_first_read(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.addCleanup(os.remove, path)
        a, b = sqlite3.connect(path, timeout=0.1), sqlite3.connect(path, timeout=0.1)
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        a.execute("CREATE TABLE state (key TEXT PRIMARY KEY, value TEXT)")
        a.commit()
        seen = []

        def fn():
            store.get_state(a, "x")                        # a read, before any write
            try:
                b.execute("BEGIN IMMEDIATE")               # another writer: must wait
                seen.append("b got in")
                b.rollback()
            except sqlite3.OperationalError:
                seen.append("locked")
            store.set_state(a, "x", 1)
        self.assertTrue(collectors.mesh_write(a, fn))
        self.assertEqual(seen, ["locked"])
        self.assertEqual(store.get_state(b, "x"), 1)

    def test_rolls_back_on_failure(self):
        c = mem_db()
        self.addCleanup(c.close)

        def fn():
            store.set_state(c, "x", 1)
            raise sqlite3.OperationalError("disk full")
        with mock.patch.object(collectors, "log"):
            self.assertFalse(collectors.mesh_write(c, fn))
        self.assertIsNone(store.get_state(c, "x"))
        self.assertFalse(c.in_transaction)


class TrustEndpointTest(unittest.TestCase):
    def setUp(self):
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.addCleanup(os.remove, self.path)
        src = db_with_pending()
        src.commit()
        dst = sqlite3.connect(self.path)
        src.backup(dst)
        src.close()
        dst.close()
        p = mock.patch.object(store, "DB_PATH", self.path)
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(mesh.TRUSTED.clear)

    def post(self, body, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.srv.server_address[1], timeout=5)
        self.addCleanup(conn.close)   # closed even when an assertion fails (#71)
        conn.request("POST", "/api/mesh/trust", body=json.dumps(body),
                     headers=headers or {"Content-Type": "application/json"})
        status = conn.getresponse().status
        conn.close()
        return status

    def test_wrong_then_right(self):
        self.assertEqual(self.post({"host": HOST, "fingerprint": "c" * 64}), 409)
        self.assertEqual(self.post({"host": "not-an-ip", "fingerprint": NEW}), 400)
        self.assertEqual(self.post({"host": HOST, "fingerprint": "zz"}), 400)
        port = self.srv.server_address[1]
        self.assertEqual(self.post({"host": HOST, "fingerprint": NEW},
                                   {"Content-Type": "application/json", "Origin": "https://evil.example",
                                    "Host": f"127.0.0.1:{port}"}), 403)
        self.assertEqual(self.post({"host": HOST, "fingerprint": NEW}), 200)
        c = store.db()
        self.addCleanup(c.close)
        self.assertEqual(store.get_state(c, mesh.PINS_STATE_KEY), {HOST: NEW})

    def test_damaged_pins_or_busy_database_answer_503(self):
        c = store.db()
        self.addCleanup(c.close)
        c.execute("INSERT OR REPLACE INTO state VALUES (?, '{not json')", (mesh.PINS_STATE_KEY,))
        c.commit()
        self.assertEqual(self.post({"host": HOST, "fingerprint": NEW}), 503)
        with mock.patch.object(mesh, "trust", side_effect=sqlite3.OperationalError("database is locked")):
            self.assertEqual(self.post({"host": HOST, "fingerprint": NEW}), 503)
        with mock.patch.object(store, "db", side_effect=sqlite3.OperationalError("unable to open database file")):
            self.assertEqual(self.post({"host": HOST, "fingerprint": NEW}), 503)

    def test_unrelated_errors_are_not_reported_as_damaged_pins(self):
        # only mesh.PinsDamaged earns the "delete the state row" answer; any other error stays
        # an unexpected one (the server drops the connection and logs it, as for any handler)
        with mock.patch.object(mesh, "trust", side_effect=ValueError("something else")), \
                mock.patch.object(Handler, "log_error"), mock.patch("sys.stderr"):
            try:
                status = self.post({"host": HOST, "fingerprint": NEW})
            except http.client.RemoteDisconnected:
                status = None
        self.assertNotEqual(status, 503)


if __name__ == "__main__":
    unittest.main()
