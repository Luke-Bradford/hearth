import json
import threading
import time
import unittest
from unittest import mock

from hearth import analysis, collectors, live, store
from tests.helpers import MAC_A, mem_db


class LeaseTest(unittest.TestCase):
    def setUp(self):
        live._until = 0.0
        self.addCleanup(setattr, live, "_until", 0.0)

    def test_on_while_viewed_off_after_the_lease(self):
        self.assertFalse(live.active(1000))
        live.touch(1000)
        self.assertTrue(live.active(1000 + live.LEASE_S - 1))
        self.assertFalse(live.active(1000 + live.LEASE_S + 1))

    def test_an_early_touch_never_shortens_the_lease(self):
        live.touch(2000)
        live.touch(1990)
        self.assertTrue(live.active(2000 + live.LEASE_S - 1))


class WakeIfTest(unittest.TestCase):
    def test_background_wait_ends_when_a_viewer_arrives(self):
        stop, ev = threading.Event(), threading.Event()
        flag = {"on": False}
        threading.Timer(0.05, lambda: flag.update(on=True)).start()
        t = time.monotonic()
        self.assertEqual(collectors.wait_either(stop, ev, 30, step=0.01, wake_if=lambda: flag["on"]), "live")
        self.assertLess(time.monotonic() - t, 5)


class LiveViewTest(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)
        live._latest.clear()
        self.addCleanup(live._latest.clear)
        live.set_host(None)
        self.addCleanup(live.set_host, None)
        analysis.clear_cache()  # the live name lookup is cached between requests
        self.addCleanup(analysis.clear_cache)

    def test_figures_from_memory_and_the_latest_router_reading(self):
        now = time.time()
        live.record_ping("gateway", now - 1, 9.5)
        live.record_ping("inet:1.1.1.1", now - 1, 17.0)
        live.record_ping("inet:8.8.8.8", now - 1, 21.0)
        live.record_ping("inet:9.9.9.9", now - 60, 5.0)          # stale: ignored
        live.set_host({"cpu_pct": 7.0, "mem_avail": 64, "mem_total": 128})
        store.save_router_clients(self.c, now, [{"mac": MAC_A, "ip": "192.168.1.135", "name": "Mac",
                                                 "online": True, "rx_total": 0, "tx_total": 0}])
        store.add_usage(self.c, now - 3, 5, {MAC_A: (20_000_000, 1_000_000)})
        v = analysis.live_view(self.c)
        self.assertEqual((v["internet_ms"], v["internet_up"], v["router_ms"]), (17.0, True, 9.5))
        self.assertAlmostEqual(v["down_mbps"], 32.0, places=1)
        self.assertEqual(v["busiest"]["name"], "Mac")
        self.assertEqual((v["cpu_pct"], v["mem_used_pct"]), (7.0, 50.0))

    def test_stale_host_sample_and_router_rounding(self):
        now = time.time()
        live.record_ping("gateway", now - 1, 9.4567)
        live.set_host({"cpu_pct": 7.0, "mem_avail": 64, "mem_total": 128}, ts=now - 60)  # before a lapse
        v = analysis.live_view(self.c)
        self.assertEqual(v["router_ms"], 9.5)
        self.assertEqual((v["cpu_pct"], v["mem_used_pct"]), (None, None))

    def test_cached_names_outlive_the_request_connection(self):
        # each request opens and closes its own connection; the cached name lookup must not
        # hold on to one
        now = time.time()
        for db in (mem_db(), mem_db()):
            store.save_router_clients(db, now, [{"mac": MAC_A, "ip": "192.168.1.135", "name": "Mac",
                                                 "online": True, "rx_total": 0, "tx_total": 0}])
            store.add_usage(db, now - 3, 5, {MAC_A: (20_000_000, 0)})
            self.assertEqual(analysis.live_view(db)["busiest"]["name"], "Mac")
            db.close()

    def test_stalled_pinger_is_unknown_not_down(self):
        live.record_ping("inet:1.1.1.1", time.time() - 60, 17.0)
        live.record_ping("gateway", time.time() - 60, 9.0)
        v = analysis.live_view(self.c)
        self.assertIsNone(v["internet_up"])
        self.assertIsNone(v["router_ms"])

    def test_internet_down_and_nothing_known(self):
        now = time.time()
        live.record_ping("inet:1.1.1.1", now - 1, None)
        v = analysis.live_view(self.c)
        self.assertIs(v["internet_up"], False)
        self.assertIsNone(v["down_mbps"])
        self.assertIsNone(v["cpu_pct"])


class EndpointTouchesTest(unittest.TestCase):
    def test_api_live_turns_live_mode_on(self):
        import http.client
        from http.server import ThreadingHTTPServer
        from hearth.web import Handler
        live._until = 0.0
        self.addCleanup(setattr, live, "_until", 0.0)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        with mock.patch.object(store, "db", side_effect=lambda: mem_db()):  # the handler closes it
            conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
            self.addCleanup(conn.close)   # closed even when an assertion fails (#71)
            conn.request("GET", "/api/live")
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            # the dashboard's version, so an open page reloads itself after an update
            # mtime_ns-size of the markup, then of the script: an update to either reloads the page
            self.assertRegex(json.loads(resp.read())["ui"], r"^\d+-\d+/\d+-\d+$")
            conn.request("GET", "/")
            page = conn.getresponse()
            page.read()
            self.assertEqual(page.getheader("Cache-Control"), "no-cache")  # never a stale copy
            conn.close()
        self.assertTrue(live.active())


if __name__ == "__main__":
    unittest.main()
