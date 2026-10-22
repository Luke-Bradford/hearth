import contextlib
import io
import sqlite3
import time
import unittest
from unittest import mock

from hearth import store, topology as T, web
from hearth.config import DEFAULTS
from hearth.main import Server
from hearth.web import RECENT_RADIO_S, _wifi
from tests.helpers import GW, make_series, spikes_every


class FastestBandIsLocalTest(unittest.TestCase):
    # this computer, PC, Mac, a VM and the nearby mesh node share a segment; the TV side hangs
    # off another mesh node beyond the router
    SPEC = {"pc": (5, 3), "mac": (4.4, 2), "ha": (5.2, 2), "deco": (4.8, 2),
            "tv": (13, 2), "hue": (14, 2), "shield": (13.5, 2), GW: (9, 4)}
    DEVICES = ["pc", "mac", "ha", "deco", "tv", "hue", "shield"]

    def test_local_hiccups_shared_with_the_router_do_not_make_a_relay(self):
        # the local segment stalls and takes the router's replies with it. Only 4 of 7 devices
        # are hit - under the "measuring machine" threshold - so the spikes count as shared
        stalls = spikes_every(12, {"pc", "mac", "ha", "deco", GW})
        r = T.infer(make_series(self.SPEC, events=stalls), self.DEVICES, GW)
        self.assertEqual(r["noise_buckets"], 0)
        self.assertGreaterEqual(r["roles"]["mac"]["shared"], T.SHARED_THRESHOLD)
        self.assertEqual(sorted(r["local"]), ["deco", "ha", "mac", "pc"])
        self.assertEqual(r["relays"], [])
        self.assertEqual([sorted(g) for g in r["branches"]], [["hue", "shield", "tv"]])

    def test_unstable_fast_device_is_not_the_local_band(self):
        # a sleepy phone with a very fast floor must neither become band 0 nor be relabelled local
        spec = {"phone": (1.0, 1), "mac": (4.4, 2), "tv1": (7.4, 2), GW: (10.3, 4)}
        naps = spikes_every(20, {"phone"}, every=60, dur=30, extra=None)
        r = T.infer(make_series(spec, events=naps), ["phone", "mac", "tv1"], GW)
        self.assertEqual(r["roles"]["phone"]["role"], T.ROLE_UNSTABLE)
        self.assertEqual(r["local"], ["mac"])

    def test_remembered_relay_in_fastest_band_becomes_local(self):
        spec = {"pc": (5, 3), "mac": (4.4, 2), GW: (10.3, 4)}
        previous = {"mac": {"role": T.ROLE_RELAY, "confident": True}}
        r = T.infer(make_series(spec), ["pc", "mac"], GW, previous=previous)
        self.assertEqual(sorted(r["local"]), ["mac", "pc"])

    def test_slower_band_sharing_router_trouble_is_still_a_relay(self):
        spec = {"pc": (5, 3), "mac": (4.4, 2), "tv1": (7.4, 2), "tv2": (7.5, 2), GW: (10.3, 4)}
        events = spikes_every(12, {"pc", "mac", GW}) + spikes_every(12, {"tv1", "tv2", GW}, every=97)
        r = T.infer(make_series(spec, events=events), ["pc", "mac", "tv1", "tv2"], GW)
        self.assertEqual(sorted(r["local"]), ["mac", "pc"])
        self.assertEqual([sorted(g) for g in r["relays"]], [["tv1", "tv2"]])


class DisconnectNoiseTest(unittest.TestCase):
    def _handle(self, exc):
        srv = Server.__new__(Server)  # handle_error doesn't need a bound socket
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            try:
                raise exc
            except Exception:
                srv.handle_error(None, ("192.168.1.10", 50000))
        return err.getvalue()

    def test_browser_disconnects_are_silent(self):
        for exc in (ConnectionResetError(10054, "reset"), ConnectionAbortedError(), BrokenPipeError()):
            self.assertEqual(self._handle(exc), "", exc)

    def test_listen_queue_takes_a_dashboard_burst(self):
        self.assertGreaterEqual(Server.request_queue_size, 32)

    def test_concurrent_handlers_are_capped(self):
        import http.client
        import socket
        import threading
        from hearth.web import Handler

        class Small(Server):
            max_handlers = 2

        srv = Small(("127.0.0.1", 0), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        port = srv.server_address[1]
        # two clients connect and send nothing: each holds a handler (until Handler.timeout)
        stalled = [socket.create_connection(("127.0.0.1", port)) for _ in range(2)]
        for s in stalled:
            self.addCleanup(s.close)
        answered = threading.Event()

        def real_request():
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            c.request("GET", "/no-such-page")
            c.getresponse().read()
            c.close()
            answered.set()

        threading.Thread(target=real_request, daemon=True).start()
        self.assertFalse(answered.wait(0.7))  # no free handler: it waits in the listen queue
        stalled[0].close()                    # that handler ends, freeing its slot
        self.assertTrue(answered.wait(5))

    def test_real_errors_still_print(self):
        self.assertIn("ValueError", self._handle(ValueError("boom")))


class RecentRadiosTest(unittest.TestCase):
    def test_radios_not_heard_recently_are_not_listed(self):
        c = sqlite3.connect(":memory:")
        self.addCleanup(c.close)
        c.executescript(store.SCHEMA)
        for col in ("vendor", "friendly", "model"):
            c.execute(f"ALTER TABLE devices ADD COLUMN {col} TEXT")
        now = time.time()
        c.executemany("INSERT INTO wifi VALUES (?,?,?,?,?,?,?,?)", [
            (now - 30, "Home", "aa:aa:aa:aa:aa:01", "5 GHz", 40, 80, 10, 2),                     # on air
            (now - RECENT_RADIO_S - 120, "Home", "aa:aa:aa:aa:aa:02", "5 GHz", 36, 87, 2, 0),   # unplugged
        ])
        listed = {w["bssid"] for w in _wifi(c, 60)}
        self.assertEqual(listed, {"aa:aa:aa:aa:aa:01"})

    def test_bad_scan_interval_in_config_falls_back_to_default(self):
        for bad in ("30s", None):
            with mock.patch.dict(web.CFG, {"wifi_scan_interval_s": bad}):
                self.assertEqual(web._scan_interval_s(), float(DEFAULTS["wifi_scan_interval_s"]))


if __name__ == "__main__":
    unittest.main()
