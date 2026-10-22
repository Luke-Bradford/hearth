"""Step 5, part 1 (#105): the Setup checklist."""
import http.client
import json
import os
import shutil
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest import mock

from http.server import ThreadingHTTPServer

from hearth import analysis, levels as lv, mesh, net, notify, router, settings, setup, sources, store
from hearth.web import Handler
from hearth.config import inet_target
from tests.helpers import mem_db

GW = "192.168.1.254"


class ChecklistTest(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)
        self.vendors = {}
        self.toggles = {"alert_attention": True}
        for p in (mock.patch.object(analysis, "_gateway_ip", return_value=GW),
                  mock.patch.object(net, "vendor", side_effect=lambda mac: self.vendors.get(mac, "")),
                  mock.patch.object(settings, "value", side_effect=lambda k: self.toggles.get(k)),
                  mock.patch.object(setup, "has_password", return_value=False),
                  mock.patch.object(setup.notify, "channels", return_value=([], None))):   # never the real file
            p.start()
            self.addCleanup(p.stop)

    def items(self):
        return {i["key"]: i for i in setup.checklist(self.c, time.time())["items"]}

    def test_a_fresh_install(self):
        i = self.items()
        self.assertEqual(i["measuring"]["level"], lv.BAD)
        self.assertIn("firewall", i["measuring"]["action"])
        self.assertEqual(i["network"]["level"], lv.UNKNOWN)
        self.assertEqual(i["network"]["text"], "No devices found yet.")             # #108: not "0 devices online"
        self.assertIn("5 minutes", i["network"]["action"])
        self.assertTrue(i["router"]["optional"])
        self.assertIn("couldn't tell what make", i["router"]["text"])
        self.assertEqual(i["mesh"]["text"], "No supported mesh found - the map is worked out from reply times.")

    def test_measuring_once_the_internet_replies(self):
        self.c.execute("INSERT INTO pings VALUES (?, ?, ?)", (time.time() - 5, inet_target("1.1.1.1"), 18.0))
        with mock.patch.dict(setup.CFG, {"core_interval_s": 2}):
            m = self.items()["measuring"]
        self.assertEqual((m["level"], m["text"]), (lv.OK, "Pinging the internet every 2 s."))   # #108: the setting, not "every second"

    def test_a_glinet_router_and_tplink_devices_get_the_next_step(self):
        self.c.execute("INSERT INTO devices (ip, mac, online) VALUES (?, ?, 1)", (GW, "94:83:c4:00:00:01"))
        self.c.execute("INSERT INTO devices (ip, mac, online) VALUES (?, ?, 1)", ("192.168.1.231", "20:e1:5d:00:00:01"))
        self.vendors = {"94:83:c4:00:00:01": "GL Technologies (Hong Kong) Limited", "20:e1:5d:00:00:01": "TP-Link Systems Inc."}
        i = self.items()
        self.assertIn("looks like a GL Technologies", i["router"]["text"])
        self.assertIn("router's admin password", i["router"]["action"])
        self.assertIn("If they're Deco mesh units", i["mesh"]["text"])

    def test_working_and_failing_sources(self):
        sources.report_ok(self.c, sources.ROUTER)
        sources.report_error(self.c, sources.MESH, "login refused")
        sources.report_unconfigured(self.c, sources.UPNP, "the router doesn't answer UPnP")
        sources.report_unconfigured(self.c, sources.DNS)
        i = self.items()
        self.assertEqual(i["dns"]["text"], "Turned off.")                           # #108: not "Starting."
        self.assertEqual(i["router"]["level"], lv.OK)
        self.assertEqual((i["mesh"]["level"], i["mesh"]["text"]), (lv.BAD, "Set up, but failing: login refused."))
        self.assertEqual(i["upnp"]["text"], "The router doesn't answer UPnP.")

    def test_notifications(self):
        self.assertEqual((self.items()["notify"]["level"], self.items()["notify"]["optional"]), (lv.UNKNOWN, True))
        sources.report_ok(self.c, sources.NOTIFY, {"channels": ["ntfy", "Discord"]})
        self.assertEqual(self.items()["notify"]["text"], "Alerts are sent to ntfy and Discord.")
        sources.report_error(self.c, sources.NOTIFY, "ntfy: HTTP 403")
        i = self.items()["notify"]
        self.assertEqual((i["level"], i["text"]), (lv.BAD, "Set up, but failing: ntfy: HTTP 403."))

    def test_alerts_off_says_so(self):
        self.toggles = {}
        i = self.items()
        self.assertEqual((i["alerts"]["level"], i["alerts"]["action"]), (lv.UNKNOWN, "Turn them on in Settings, below."))

    def test_passwords_are_only_ever_set_or_not(self):
        out = setup.checklist(self.c, time.time())
        self.assertEqual(out["credentials"], {"router": False, "mesh": False, "notify": [None, None], "notify_token": False})
        self.assertTrue(out["credentials_file"])


class ReaderWaitsForAPasswordTest(unittest.TestCase):
    """Step 5.2: a password added from the page starts the reader - no restart."""

    def test_the_mesh_reader_starts_once_a_password_appears(self):
        import threading as th
        from hearth import collectors
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "router.env")
        stop, started = th.Event(), th.Event()

        def first_read(*a, **k):        # the first thing the reader does once configured
            started.set()
            stop.set()
            raise RuntimeError("stop here")
        with mock.patch.object(collectors, "CREDENTIALS_RECHECK_S", 0.05), \
             mock.patch.object(collectors.router, "credentials_path", return_value=path), \
             mock.patch.object(collectors, "_report_unconfigured"), \
             mock.patch.object(collectors.store, "db", side_effect=first_read), \
             mock.patch.object(collectors, "log"):
            t = th.Thread(target=lambda: self._run(collectors.mesh_loop, stop), daemon=True)
            t.start()
            time.sleep(0.2)
            self.assertFalse(started.is_set())                       # no password: waiting
            setup.save_credentials({"mesh": "deco pw"}, path)
            self.assertTrue(started.wait(2))                          # added: it starts by itself
            t.join(2)

    @staticmethod
    def _run(loop, stop):
        try:
            loop(stop)
        except RuntimeError:
            pass


class CredentialsFileTest(unittest.TestCase):
    """Step 5.2: passwords written from the page."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.path = os.path.join(self.dir, "sub", "router.env")

    def read(self):
        with open(self.path, encoding="utf-8") as f:
            return f.read()

    def test_created_kept_and_replaced(self):
        setup.save_credentials({"router": "first pass"}, self.path)               # folder and file created
        self.assertEqual(self.read(), "GLINET_PASSWORD=first pass\n")
        with open(self.path, "a", encoding="utf-8") as f:
            f.write("# a note\nOTHER=1\n")
        setup.save_credentials({"router": "second", "mesh": "deco pw"}, self.path)
        self.assertEqual(self.read().splitlines(), ["# a note", "OTHER=1", "GLINET_PASSWORD=second", "DECO_PASSWORD=deco pw"])
        self.assertEqual(router.read_password(self.path), "second")              # the readers read it back
        self.assertEqual(router.read_password(self.path, mesh.PASSWORD_KEY), "deco pw")
        self.assertEqual([n for n in os.listdir(os.path.dirname(self.path)) if n.endswith(".tmp")], [])

    def test_bad_values_write_nothing(self):
        for bad in ({}, [], {"router": ""}, {"router": "x" * 129}, {"router": "a\nDECO_PASSWORD=evil"},
                    {"router": "tab\there"}, {"router": " padded"}, {"router": 5}, {"admin": "x"},
                    {"router": "ok", "mesh": "bad\r"}):
            with self.assertRaises(setup.Invalid, msg=bad):
                setup.save_credentials(bad, self.path)
        self.assertFalse(os.path.exists(self.path))

    def test_two_saves_at_once_keep_both(self):
        # #109: the read-modify-write is locked - the router and Deco passwords saved together both stay
        import threading as th
        real = setup._write

        def slow(*a):
            time.sleep(0.05)                        # widen the window two unlocked writes would race in
            return real(*a)
        with mock.patch.object(setup, "_write", side_effect=slow):
            ts = [th.Thread(target=setup.save_credentials, args=({k: f"{k} pw"}, self.path)) for k in ("router", "mesh")]
            for t in ts:
                t.start()
            for t in ts:
                t.join(5)
        self.assertEqual(sorted(self.read().splitlines()), ["DECO_PASSWORD=mesh pw", "GLINET_PASSWORD=router pw"])

    def test_an_unreadable_file_reads_as_no_password(self):
        # #109: the readers check every 15 s; a file they can't read must never raise
        with open(self.path if os.path.isdir(os.path.dirname(self.path)) else self._mk(), "wb") as f:
            f.write(bytes([0xff, 0xfe, 0x00, 0xd8]))
        self.assertFalse(router.has_password(self.path, router.PASSWORD_KEY))
        self.assertFalse(router.has_password(os.path.join(self.dir, "missing.env"), router.PASSWORD_KEY))

    def _mk(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        return self.path

    def test_an_error_never_says_the_password(self):
        with self.assertRaises(setup.Invalid) as e:
            setup.save_credentials({"router": "secret\nvalue"}, self.path)
        self.assertNotIn("secret", str(e.exception))

    def test_notification_addresses_set_and_removed(self):
        # step 6.2: kept with the passwords; "" takes a notification line out (a password can't be emptied)
        setup.save_credentials({"router": "pw", "notify": "https://ntfy.sh/my-topic", "notify_token": "tk_AgQd7"}, self.path)
        self.assertEqual(notify.channels(self.path), ([("NOTIFY_URL", "https://ntfy.sh/my-topic", notify.NTFY)], "tk_AgQd7"))
        setup.save_credentials({"notify_2": "https://discord.com/api/webhooks/1/abc", "notify": ""}, self.path)
        self.assertEqual(self.read().splitlines(), ["GLINET_PASSWORD=pw", "NOTIFY_TOKEN=tk_AgQd7",
                                                    "NOTIFY_URL_2=https://discord.com/api/webhooks/1/abc"])
        setup.save_credentials({"notify": "", "notify_token": ""}, self.path)         # removing what's gone is fine
        self.assertEqual(self.read().splitlines(), ["GLINET_PASSWORD=pw", "NOTIFY_URL_2=https://discord.com/api/webhooks/1/abc"])

    def test_bad_notification_values_write_nothing(self):
        for bad in ({"notify": "ftp://x/y"}, {"notify": "https://ntfy.sh/"}, {"notify": "https://x/\nNOTIFY_URL=evil"},
                    {"notify_2": 5}, {"notify_token": "tk bad"}, {"notify_token": "x" * 129}, {"mesh": ""},
                    {"notify": "https://ntfy.sh/t", "notify_token": "bad\r"}):
            with self.assertRaises(setup.Invalid, msg=bad):
                setup.save_credentials(bad, self.path)
        self.assertFalse(os.path.exists(self.path))
        with self.assertRaises(setup.Invalid) as e:
            setup.save_credentials({"notify": "https://secret-host:abc/x"}, self.path)
        self.assertNotIn("secret-host", str(e.exception))                              # never says the address


class CredentialsEndpointTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.path = os.path.join(self.dir, "router.env")
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        self.c = sqlite3.connect(":memory:", check_same_thread=False)
        self.c.executescript(store.SCHEMA)
        self.addCleanup(self.c.close)
        c = self.c

        class Kept:
            def __getattr__(self, name):
                return getattr(c, name)

            def close(self):
                pass
        for p in (mock.patch.object(store, "db", side_effect=lambda: Kept()),
                  mock.patch.object(router, "credentials_path", return_value=self.path)):
            p.start()
            self.addCleanup(p.stop)

    def post(self, body, origin=True):
        port = self.srv.server_address[1]
        h = {"Content-Type": "application/json"}
        if origin:
            h["Origin"] = f"http://127.0.0.1:{port}"
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        self.addCleanup(conn.close)   # closed even when an assertion fails (#71)
        conn.request("POST", "/api/setup/credentials", body=json.dumps(body).encode(), headers=h)
        r = conn.getresponse()
        raw = r.read()
        conn.close()
        return r.status, raw

    def test_set_from_this_machine_never_echoed(self):
        router.REFRESH.clear()
        status, raw = self.post({"router": "hunter2-router"})
        self.assertEqual(status, 200)
        self.assertNotIn(b"hunter2", raw)
        self.assertTrue(json.loads(raw)["credentials"]["router"])
        self.assertTrue(router.REFRESH.is_set())                                  # the reader is woken
        self.assertEqual(self.c.execute("SELECT detail FROM events WHERE kind = 'credentials'").fetchone(),
                         ("Set from the Setup panel: the router password",))

    def test_a_notification_address_from_this_machine_never_echoed(self):
        notify.WAKE.clear()
        status, raw = self.post({"notify": "https://ntfy.sh/hidden-topic-123"})
        self.assertEqual(status, 200)
        self.assertNotIn(b"hidden-topic", raw)
        self.assertEqual(json.loads(raw)["credentials"]["notify"], ["ntfy", None])   # its kind only
        self.assertTrue(notify.WAKE.is_set())                                        # the sender looks now
        self.assertEqual(self.c.execute("SELECT detail FROM events WHERE kind = 'credentials'").fetchone(),
                         ("Set from the Setup panel: notification address 1",))
        with mock.patch.object(Handler, "_local", return_value=False):
            self.assertEqual(self.post({"notify": "https://evil.example/hook"})[0], 403)   # only on this machine
        self.assertNotIn("evil", open(self.path, encoding="utf-8").read())

    def test_refused_from_another_device(self):
        with mock.patch.object(Handler, "_local", return_value=False):
            status, raw = self.post({"router": "x"})
        self.assertEqual(status, 403)
        self.assertFalse(os.path.exists(self.path))

    def test_refused_cross_site_and_bad_values(self):
        port = self.srv.server_address[1]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        self.addCleanup(conn.close)   # closed even when an assertion fails (#71)
        conn.request("POST", "/api/setup/credentials", body=b'{"router": "x"}',
                     headers={"Content-Type": "application/json", "Origin": "http://evil.example"})
        self.assertEqual(conn.getresponse().status, 403)
        conn.close()
        self.assertEqual(self.post({"router": "two\nlines"})[0], 400)
        self.assertFalse(os.path.exists(self.path))

    def test_local_is_the_tcp_peer(self):
        h = Handler.__new__(Handler)
        for addr, local in (("127.0.0.1", True), ("::1", True), ("::ffff:127.0.0.1", True),
                            ("192.168.1.20", False), ("::ffff:192.168.1.20", False), ("junk", False)):
            h.client_address = (addr, 1)
            self.assertEqual(h._local(), local, addr)


if __name__ == "__main__":
    unittest.main()
