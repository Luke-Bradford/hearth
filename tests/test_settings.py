"""Step 4, part 5 (#88): settings changed in the page - the allowlist, validation, all-or-nothing
updates, reading on use, and the endpoint's guards."""
import http.client
import ipaddress
import json
import sqlite3
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

from hearth import analysis, reports, settings, store
from hearth.web import Handler
from tests.helpers import mem_db

GW = "192.168.1.254"
LAN = ipaddress.ip_network("192.168.1.0/24")


class Base(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)
        p = mock.patch.object(settings, "_lan", return_value=LAN)
        p.start()
        self.addCleanup(p.stop)
        settings._cache["at"] = 0.0


class UpdateTest(Base):
    def test_valid_changes_are_stored_cleaned(self):
        changed = settings.update(self.c, {"usage_month_starts": 15, "dns_resolvers": ["gateway", " 9.9.9.9 "],
                                           "dns_probe_name": "example.org."}, GW)
        self.assertEqual(changed, ["dns_probe_name", "dns_resolvers", "usage_month_starts"])
        self.assertEqual(store.get_state(self.c, settings.STATE_KEY),
                         {"usage_month_starts": 15, "dns_resolvers": ["gateway", "9.9.9.9"], "dns_probe_name": "example.org"})

    def test_only_the_allowlist(self):
        for bad in ({"speedtest_schedule": "daily 03:00"}, {"router_credentials_file": "x"}, {"__proto__": 1}, {}, [], "x", None):
            with self.assertRaises(settings.Invalid, msg=bad):
                settings.update(self.c, bad, GW)
        self.assertIsNone(store.get_state(self.c, settings.STATE_KEY))

    def test_each_value_is_checked(self):
        for key, bad in (("usage_month_starts", 0), ("usage_month_starts", 29), ("usage_month_starts", "15"),
                         ("usage_month_starts", 1.5), ("usage_month_starts", True),
                         ("dns_resolvers", []), ("dns_resolvers", ["1.1.1.1"] * 2), ("dns_resolvers", ["10.0.0.1"]),
                         ("dns_resolvers", ["4.4.4.4"]), ("dns_resolvers", ["gateway", "1.1.1.1", "8.8.8.8", "9.9.9.9"]),
                         ("dns_resolvers", "1.1.1.1"), ("dns_resolvers", [5]), ("dns_resolvers", ["192.168.1.255"]),
                         ("dns_probe_name", "a..b"), ("dns_probe_name", "-x.com"), ("dns_probe_name", 5)):
            with self.assertRaises(settings.Invalid, msg=(key, bad)):
                settings.update(self.c, {key: bad}, GW)

    def test_all_or_nothing(self):
        with self.assertRaises(settings.Invalid):
            settings.update(self.c, {"usage_month_starts": 10, "dns_probe_name": "bad..name"}, GW)
        self.assertIsNone(store.get_state(self.c, settings.STATE_KEY))

    def test_none_puts_a_key_back_to_config(self):
        settings.update(self.c, {"usage_month_starts": 10, "dns_probe_name": "example.org"}, GW)
        settings.update(self.c, {"usage_month_starts": None}, GW)
        self.assertEqual(store.get_state(self.c, settings.STATE_KEY), {"dns_probe_name": "example.org"})

    def test_the_same_as_config_isnt_a_change(self):
        # the form posts every field: unchanged ones mustn't pin config.json's value
        with mock.patch.dict(settings.CFG, {"dns_probe_name": "www.google.com", "dns_resolvers": ["gateway", "1.1.1.1"],
                                            "usage_month_starts": 1}):
            settings.update(self.c, {"usage_month_starts": 12, "dns_probe_name": "www.google.com",
                                     "dns_resolvers": ["gateway", "1.1.1.1"]}, GW)
            self.assertEqual(store.get_state(self.c, settings.STATE_KEY), {"usage_month_starts": 12})

    def test_a_lan_resolver_needs_the_lan(self):
        settings.update(self.c, {"dns_resolvers": ["192.168.1.53"]}, GW)       # a Pi-hole
        with mock.patch.object(settings, "_lan", return_value=None):
            with self.assertRaises(settings.Invalid):
                settings.update(self.c, {"dns_resolvers": ["192.168.1.53"]}, GW)


class ReadTest(Base):
    def test_the_page_wins_over_config_and_is_read_on_use(self):
        with mock.patch.object(store, "db", side_effect=lambda: self._shared()):
            with mock.patch.dict(settings.CFG, {"usage_month_starts": 1}):
                self.assertEqual(reports.month_start_day(), 1)
                settings.update(self.c, {"usage_month_starts": 20}, GW)
                settings.invalidate()                                     # as the endpoint does, after its commit
                self.assertEqual(reports.month_start_day(), 20)            # no restart: the cache was dropped
                self.assertEqual(settings.view(self.c)["changed"], ["usage_month_starts"])
                self.assertEqual(settings.view(self.c)["defaults"]["usage_month_starts"], 1)

    def _shared(self):
        c = self.c

        class Kept:
            def __getattr__(self, name):
                return getattr(c, name)

            def close(self):
                pass
        return Kept()

    def test_the_cache_is_dropped_after_the_commit_not_before(self):
        # #96: update() leaves the cache alone; the caller drops it once the change is committed
        settings._cache.update(at=1e18, vals={"usage_month_starts": 3})
        settings.update(self.c, {"usage_month_starts": 9}, GW)
        self.assertEqual(settings._cache["vals"], {"usage_month_starts": 3})
        settings.invalidate()
        self.assertEqual(settings._cache["at"], 0.0)

    def test_a_damaged_row_reads_as_nothing_changed(self):
        self.c.execute("INSERT INTO state VALUES (?, ?)", (settings.STATE_KEY, json.dumps(["not", "a", "dict"])))
        self.assertEqual(settings.view(self.c)["changed"], [])

    def test_the_schedule_is_read_only(self):
        v = settings.view(self.c)
        self.assertIn("speedtest_schedule", v["read_only"])
        self.assertNotIn("speedtest_schedule", v["values"])


class EndpointTest(unittest.TestCase):
    def setUp(self):
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        # one database the server's request thread and the test both see (requests run in a thread)
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
                  mock.patch.object(analysis, "_gateway_ip", return_value=GW),
                  mock.patch.object(settings, "_lan", return_value=LAN)):
            p.start()
            self.addCleanup(p.stop)

    def post(self, body, ctype="application/json", origin=None):
        host = f"127.0.0.1:{self.srv.server_address[1]}"      # http.client sends this as Host itself
        h = {"Content-Type": ctype, "Origin": origin or f"http://{host}"}
        conn = http.client.HTTPConnection("127.0.0.1", self.srv.server_address[1], timeout=5)
        self.addCleanup(conn.close)   # closed even when an assertion fails (#71)
        conn.request("POST", "/api/settings", body=body if isinstance(body, bytes) else json.dumps(body).encode(), headers=h)
        r = conn.getresponse()
        out = (r.status, json.loads(r.read() or b"{}"))
        conn.close()
        return out

    def test_a_good_change_is_saved_and_logged(self):
        status, body = self.post({"usage_month_starts": 12})
        self.assertEqual(status, 200)
        self.assertEqual(body["values"]["usage_month_starts"], 12)
        self.assertEqual(self.c.execute("SELECT detail FROM events WHERE kind = 'settings'").fetchone(),
                         ("Settings changed in the page: usage_month_starts",))

    def test_refusals(self):
        self.assertEqual(self.post({"speedtest_schedule": "daily 03:00"})[0], 400)
        self.assertEqual(self.post({"usage_month_starts": 40})[0], 400)
        self.assertIn("1 to 28", self.post({"usage_month_starts": 40})[1]["error"])
        self.assertEqual(self.post(b"not json")[0], 400)
        # #96: deep nesting can't reach a RecursionError - the body cap (1 KB) stops it first - and
        # within the cap it's just not an object
        self.assertEqual(self.post(b"[" * 5000 + b"]" * 5000)[0], 413)
        self.assertEqual(self.post(b"[" * 500 + b"]" * 500)[0], 400)
        self.assertEqual(self.post({"usage_month_starts": 5}, ctype="text/plain")[0], 415)     # no preflight-free CSRF
        self.assertEqual(self.post({"usage_month_starts": 5}, origin="http://evil.example")[0], 403)
        self.assertIsNone(store.get_state(self.c, settings.STATE_KEY))


if __name__ == "__main__":
    unittest.main()
