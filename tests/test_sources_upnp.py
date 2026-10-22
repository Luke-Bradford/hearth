"""Part 4 of step 2 (#64): one shape for source state, and the read-only UPnP gateway reader."""
import sqlite3
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from hearth import analysis, collectors, sources, store, upnp
from tests.helpers import mem_db

GW = "192.168.1.254"
DESC = f"http://{GW}:5000/rootDesc.xml"


def description(conn_service="WANIPConnection", version=1, ctrl_common="/ctl/CmnIfCfg", ctrl_conn="/ctl/IPConn",
                url_base=None):
    base = f"<URLBase>{url_base}</URLBase>" if url_base else ""
    return (f'<?xml version="1.0" encoding="utf-8"?><root xmlns="urn:schemas-upnp-org:device-1-0">{base}<device>'
            f"<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:{version}</deviceType><deviceList><device>"
            f"<deviceType>urn:schemas-upnp-org:device:WANDevice:{version}</deviceType><serviceList><service>"
            "<serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>"
            f"<controlURL>{ctrl_common}</controlURL><SCPDURL>/cmn.xml</SCPDURL></service></serviceList><deviceList><device>"
            f"<deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:{version}</deviceType><serviceList><service>"
            f"<serviceType>urn:schemas-upnp-org:service:{conn_service}:{version}</serviceType>"
            f"<controlURL>{ctrl_conn}</controlURL><SCPDURL>/conn.xml</SCPDURL></service></serviceList>"
            "</device></deviceList></device></deviceList></device></root>").encode()


def soap_reply(action, service, **out):
    args = "".join(f"<{k}>{v}</{k}>" for k, v in out.items())
    return ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>'
            f'<u:{action}Response xmlns:u="{service}">{args}</u:{action}Response></s:Body></s:Envelope>').encode()


class FakeRouter:
    """Answers the description and the read actions; records every request."""

    def __init__(self, desc=None, rx=1000, tx=200):
        self.desc, self.rx, self.tx, self.asked = desc or description(), rx, tx, []

    def __call__(self, url, gateway, body=None, headers=None):
        upnp.pinned(url, gateway)                           # what http_get enforces
        self.asked.append((url, (headers or {}).get("SOAPAction")))
        if body is None:
            return self.desc
        service, action = headers["SOAPAction"].strip('"').split("#")
        out = {"GetTotalBytesReceived": {"NewTotalBytesReceived": self.rx},
               "GetTotalBytesSent": {"NewTotalBytesSent": self.tx},
               "GetCommonLinkProperties": {"NewPhysicalLinkStatus": "Up", "NewLayer1DownstreamMaxBitRate": 80000000,
                                           "NewLayer1UpstreamMaxBitRate": 20000000},
               "GetExternalIPAddress": {"NewExternalIPAddress": "81.2.69.142"},
               "GetStatusInfo": {"NewConnectionStatus": "Connected", "NewUptime": 3600}}[action]
        return soap_reply(action, service, **out)


class SourcesTest(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)

    def test_ok_error_and_not_set_up(self):
        sources.report_ok(self.c, "router", {"host": GW}, now=100)
        sources.report_error(self.c, "router", "unreachable", now=200)
        sources.report_error(self.c, "router", "still unreachable", now=300)
        st = sources.states(self.c)["router"]
        self.assertEqual((st["ok"], st["since"], st["last_ok"], st["error"]), (False, 200, 100, "still unreachable"))
        self.assertEqual(st["detail"], {"host": GW})              # what it last said about itself
        sources.report_ok(self.c, "router", now=400)
        self.assertEqual((sources.states(self.c)["router"]["ok"], sources.states(self.c)["router"]["since"]), (True, None))
        sources.report_unconfigured(self.c, "mesh", "no DECO_PASSWORD set up")
        self.assertEqual(sources.states(self.c)["mesh"]["configured"], False)
        self.assertEqual(sources.failing(sources.states(self.c)), 0)
        sources.report_error(self.c, "upnp", "lost", now=500)
        self.assertEqual(sources.failing(sources.states(self.c)), 1)

    def test_status_carries_every_source_and_the_failing_count(self):
        sources.report_error(self.c, "router", "unreachable", now=100)
        view = analysis.sources_view(self.c, time.time())
        self.assertEqual(set(view["sources"]), {"router", "history"})
        self.assertEqual(view["sources_failing"], 1)              # the router; history is still starting
        self.assertIsNone(view["sources"]["history"]["ok"])
        with mock.patch.object(analysis, "HEARTH_STARTED", time.time() - analysis.HISTORY_STARTING_S - 1):
            later = analysis.sources_view(self.c, time.time())
        self.assertEqual(later["sources_failing"], 2)             # past the start, unsaved history is failing

    def test_not_set_up_again_and_again_writes_once(self):
        with mock.patch.object(store, "set_state", wraps=store.set_state) as w:
            for _ in range(3):
                sources.report_unconfigured(self.c, "upnp", "the router doesn't answer UPnP")
            self.assertEqual(w.call_count, 1)                     # unchanged: not rewritten (#71)
            sources.report_unconfigured(self.c, "upnp", "turned off in config.json")
            self.assertEqual(w.call_count, 2)                     # a new reason is written
        self.assertEqual(sources.read(self.c, "upnp")["detail"], {"why": "turned off in config.json"})

    def test_a_zero_timestamp_is_a_timestamp(self):
        sources.report_ok(self.c, "router", now=0)
        self.assertEqual(sources.read(self.c, "router")["last_ok"], 0)

    def test_a_damaged_row_reads_as_never_reported(self):
        self.c.execute("INSERT OR REPLACE INTO state VALUES ('source:router', '{bad')")
        self.assertEqual(sources.states(self.c), {})


class PinningTest(unittest.TestCase):
    def test_only_http_on_the_gateways_own_address(self):
        self.assertEqual(upnp.pinned("/ctl/x", GW, DESC), f"http://{GW}:5000/ctl/x")
        self.assertEqual(upnp.pinned(f"http://{GW}:49152/a", GW), f"http://{GW}:49152/a")
        for bad in ("http://192.168.1.10:5000/x", "http://router.lan/x", "http://127.0.0.1/x", f"https://{GW}/x",
                    "ftp://192.168.1.254/x", f"http://{GW}:99999/x", "//evil.example/x"):
            with self.assertRaises(upnp.UpnpError, msg=bad):
                upnp.pinned(bad, GW, DESC)


class ParseTest(unittest.TestCase):
    def test_strict_utf8_without_dtds(self):
        good = b'<?xml version="1.0" encoding="UTF-8"?><a><b>x</b></a>'
        self.assertEqual(upnp.parse_xml(good).find("b").text, "x")
        self.assertEqual(upnp.parse_xml(b"\xef\xbb\xbf" + good).find("b").text, "x")     # a UTF-8 BOM is fine
        dtd = '<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x "xx">]><a>&x;</a>'
        for bad in (dtd.encode(),
                    dtd.encode("utf-16"),                                     # with a byte-order mark
                    dtd.encode("utf-16-le"),                                  # without one
                    '<?xml version="1.0" encoding="ISO-8859-1"?><a/>'.encode(),
                    b'<?xml version="1.0"?><!doctype a><a/>',
                    b'<a><!ENTITY y "z"></a>',
                    b"\xff\xfe<\x00a\x00/\x00>\x00",
                    b"<a>\xff</a>",                                           # not UTF-8
                    b"<a><b></a>"):                                           # not XML
            with self.assertRaises(upnp.UpnpError, msg=bad[:40]):
                upnp.parse_xml(bad)


class ServicesTest(unittest.TestCase):
    def test_v1_v2_ip_and_ppp(self):
        for version in (1, 2):
            for conn in ("WANIPConnection", "WANPPPConnection"):
                svc = upnp.services(upnp.parse_xml(description(conn, version)), DESC, GW)
                self.assertEqual(svc["WANCommonInterfaceConfig"][1], f"http://{GW}:5000/ctl/CmnIfCfg")
                self.assertIn(conn, svc)

    def test_control_urls_pointing_away_are_refused(self):
        svc = upnp.services(upnp.parse_xml(description(ctrl_conn="http://192.168.1.10/steal")), DESC, GW)
        self.assertNotIn("WANIPConnection", svc)                   # left out
        self.assertIn("WANCommonInterfaceConfig", svc)
        with self.assertRaises(upnp.UpnpError):                    # nothing usable left: why is raised
            upnp.services(upnp.parse_xml(description(url_base="http://127.0.0.1:5000/")), DESC, GW)


class SoapTest(unittest.TestCase):
    def test_only_read_actions_are_ever_sent(self):
        router = FakeRouter()
        for action in ("AddPortMapping", "DeletePortMapping", "SetConnectionType", "ForceTermination"):
            with self.assertRaises(upnp.UpnpError):
                upnp.soap(f"http://{GW}:5000/ctl/IPConn", "urn:x", action, GW, router)
        self.assertEqual(router.asked, [])

    def test_a_full_read(self):
        router = FakeRouter()
        r = upnp.Gateway(GW, DESC, router).read()
        self.assertEqual(r, {"rx_total": 1000, "tx_total": 200, "link_up": True, "down_bps": 80000000,
                             "up_bps": 20000000, "public_ip": "81.2.69.142", "connected": True, "uptime_s": 3600})
        self.assertTrue(all(u.startswith(f"http://{GW}:5000/") for u, _ in router.asked))
        actions = {a.strip('"').split("#")[1] for _, a in router.asked if a}
        self.assertTrue(actions <= upnp.ALLOWED_ACTIONS)


class PublicIpTest(unittest.TestCase):
    def test_only_global_addresses(self):
        self.assertEqual(upnp.public_ip(" 81.2.69.142 "), "81.2.69.142")
        for not_public in ("0.0.0.0", "192.168.1.2", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.1.1",
                           "203.0.113.7", "", None, "garbage"):
            self.assertIsNone(upnp.public_ip(not_public), not_public)


class OptionalActionsTest(unittest.TestCase):
    def test_a_router_with_only_the_counters_still_reads(self):
        class CountersOnly(FakeRouter):
            def __call__(self, url, gateway, body=None, headers=None):
                if body is not None and not any(a in headers["SOAPAction"] for a in ("GetTotalBytes",)):
                    raise upnp.UpnpError("the router answered UPnP with HTTP 500")   # a UPnP fault
                return super().__call__(url, gateway, body, headers)
        r = upnp.Gateway(GW, DESC, CountersOnly()).read()
        self.assertEqual((r["rx_total"], r["tx_total"]), (1000, 200))
        self.assertEqual({k: r[k] for k in ("link_up", "down_bps", "public_ip", "connected", "uptime_s")},
                         dict.fromkeys(("link_up", "down_bps", "public_ip", "connected", "uptime_s")))

    def test_the_counters_themselves_are_required(self):
        class NoCounters(FakeRouter):
            def __call__(self, url, gateway, body=None, headers=None):
                if body is not None and "GetTotalBytesReceived" in headers["SOAPAction"]:
                    raise upnp.UpnpError("the router answered UPnP with HTTP 500")
                return super().__call__(url, gateway, body, headers)
        with self.assertRaises(upnp.UpnpError):
            upnp.Gateway(GW, DESC, NoCounters()).read()


class CountersTest(unittest.TestCase):
    def test_wrap_versus_restart(self):
        self.assertEqual(upnp.counter_delta(100, 600, 60, 10 ** 8), 500)
        self.assertEqual(upnp.counter_delta(2 ** 32 - 100, 400, 60, 10 ** 8), 500)          # wrapped
        self.assertIsNone(upnp.counter_delta(3_000_000_000, 1_000, 60, 10 ** 6))           # a restart
        self.assertIsNone(upnp.counter_delta(None, 5, 60, None))
        self.assertIsNone(upnp.counter_delta(5, 6, 0, None))


class DiscoverTest(unittest.TestCase):
    class Sock:
        def __init__(self, answers):
            self.answers, self.sent = list(answers), []

        def settimeout(self, t):
            pass

        def sendto(self, data, addr):
            self.sent.append((data, addr))

        def recvfrom(self, n):
            if not self.answers:
                raise upnp.socket.timeout()
            return self.answers.pop(0)

    def test_only_the_gateway_counts(self):
        rogue = (b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.66:1900/desc.xml\r\n\r\n", ("192.168.1.66", 1900))
        real = (f"HTTP/1.1 200 OK\r\nLOCATION: {DESC}\r\n\r\n".encode(), (GW, 1900))
        sock = self.Sock([rogue, real])
        self.assertEqual(upnp.discover(GW, sock=sock), DESC)
        self.assertEqual(len(sock.sent), 2)                       # IGD v1 and v2
        self.assertIsNone(upnp.discover(GW, sock=self.Sock([rogue])))
        away = (b"HTTP/1.1 200 OK\r\nLOCATION: http://127.0.0.1:1900/desc.xml\r\n\r\n", (GW, 1900))
        self.assertIsNone(upnp.discover(GW, sock=self.Sock([away])))   # the gateway, pointing elsewhere

    def test_a_chatty_device_cant_keep_the_search_going(self):
        rogue = (b"HTTP/1.1 200 OK\r\n\r\n", ("192.168.1.66", 1900))

        class Endless(self.Sock):
            def recvfrom(self, n):
                time.sleep(0.01)
                return rogue                          # an answer every 10 ms, forever
        t = time.monotonic()
        self.assertIsNone(upnp.discover(GW, timeout=0.3, sock=Endless([])))
        self.assertLess(time.monotonic() - t, 2.0)

    def test_a_stray_socket_error_doesnt_end_the_search(self):
        real = (f"HTTP/1.1 200 OK\r\nLOCATION: {DESC}\r\n\r\n".encode(), (GW, 1900))

        class Flaky(self.Sock):
            def recvfrom(self, n):
                if not getattr(self, "hiccup", False):
                    self.hiccup = True
                    raise ConnectionResetError(10054, "an ICMP port unreachable")
                return super().recvfrom(n)
        self.assertEqual(upnp.discover(GW, sock=Flaky([real])), DESC)

    def test_the_search_uses_the_interface_towards_the_gateway(self):
        self.assertEqual(upnp.local_address_towards("127.0.0.1"), "127.0.0.1")
        self.assertIsNone(upnp.local_address_towards("not an address"))


class RedirectTest(unittest.TestCase):
    def test_redirects_arent_followed(self):
        class Redirect(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.2/elsewhere")
                self.end_headers()

            def log_message(self, *a):
                pass
        srv = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        with self.assertRaises(upnp.UpnpError) as cm:
            upnp.http_get(f"http://127.0.0.1:{srv.server_address[1]}/rootDesc.xml", "127.0.0.1")
        self.assertIn("302", str(cm.exception))

    def test_a_trickling_reply_is_cut_off_as_a_whole(self):
        class Trickle(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "40")
                self.end_headers()
                try:
                    for _ in range(40):                # a byte every 0.2 s: each read is quick, the whole isn't
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        time.sleep(0.2)
                except OSError:
                    pass                               # the client gave up, as it should

            def log_message(self, *a):
                pass
        srv = ThreadingHTTPServer(("127.0.0.1", 0), Trickle)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        t = time.monotonic()
        with mock.patch.object(upnp, "TIMEOUT_S", 1), self.assertRaises(upnp.UpnpError) as cm:
            upnp.http_get(f"http://127.0.0.1:{srv.server_address[1]}/rootDesc.xml", "127.0.0.1")
        self.assertIn("too long", str(cm.exception))
        self.assertLess(time.monotonic() - t, 4.0)            # not the 8 s the reply would take


class NoClose:
    """The test's connection, handed to code that closes its own: close() leaves it open."""

    def __init__(self, conn):
        self._conn = conn

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def close(self):
        pass


class LoopTest(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)

    def test_never_found_lost_and_forgotten(self):
        collectors.upnp_absent(self.c, "no answer", 1000.0)
        self.assertFalse(sources.read(self.c, "upnp")["configured"])         # never worked: not set up
        sources.report_ok(self.c, "upnp", now=2000.0)
        collectors.upnp_absent(self.c, "the router doesn't answer UPnP", 2100.0)
        st = sources.read(self.c, "upnp")
        self.assertEqual((st["configured"], st["ok"]), (True, False))      # worked, now lost: a failure
        collectors.upnp_absent(self.c, "still nothing", 2000.0 + collectors.UPNP_FORGET_S + 1)
        self.assertFalse(sources.read(self.c, "upnp")["configured"])         # a week on: forgotten

    def test_record_traffic_wraps_and_public_ip_changes(self):
        r1 = {"rx_total": 2 ** 32 - 100, "tx_total": 10, "down_bps": 10 ** 8, "up_bps": 10 ** 7, "public_ip": "203.0.113.7"}
        collectors.record_upnp(self.c, r1, None, 1000.0)
        r2 = {**r1, "rx_total": 400, "tx_total": 60, "public_ip": "203.0.113.9"}
        collectors.record_upnp(self.c, r2, (1000.0, r1), 1060.0)
        self.assertEqual(self.c.execute("SELECT rx, tx, dur FROM traffic_wan").fetchall(), [(500, 50, 60.0)])
        ev = [d for (d,) in self.c.execute("SELECT detail FROM events WHERE kind='public_ip'")]
        self.assertEqual(len(ev), 1)
        self.assertIn("203.0.113.9", ev[0])
        self.assertTrue(sources.read(self.c, "upnp")["ok"])

    def test_unexpected_errors_dont_end_the_reader(self):
        stop, waits = threading.Event(), []

        def wait(t):
            waits.append(t)
            if len(waits) >= 2:
                stop.set()
            return stop.is_set()
        locked = sqlite3.OperationalError("database is locked")
        with mock.patch.object(collectors.store, "db", side_effect=lambda: NoClose(self.c)), \
                mock.patch.object(collectors.analysis, "_gateway_ip", side_effect=locked), \
                mock.patch.object(collectors, "log"), mock.patch.object(stop, "wait", side_effect=wait):
            collectors.upnp_loop(stop)
        self.assertEqual(len(waits), 2)                           # went round twice: still running
        self.assertIn("OperationalError", sources.read(self.c, "upnp")["detail"]["why"])

    def test_a_failed_search_keeps_the_30_minute_cadence(self):
        stop, waits, clock = threading.Event(), [], [10_000.0]

        def wait(t):
            waits.append(t)
            clock[0] += 60                                       # a minute between turns
            if len(waits) >= 3:
                stop.set()
            return stop.is_set()
        searches = []

        def discover(gw):
            searches.append(gw)
            raise OSError("network is unreachable")             # the search itself fails
        with mock.patch.object(collectors.store, "db", side_effect=lambda: NoClose(self.c)), \
                mock.patch.object(collectors.analysis, "_gateway_ip", return_value=GW), \
                mock.patch.object(collectors.upnp, "discover", side_effect=discover), \
                mock.patch.object(collectors.time, "time", side_effect=lambda: clock[0]), \
                mock.patch.object(collectors, "log"), mock.patch.object(stop, "wait", side_effect=wait):
            collectors.upnp_loop(stop)
        self.assertEqual(len(searches), 1)                       # not once a minute

    def run_turns(self, turns, discover, gateway_cls):
        stop, waits, clock = threading.Event(), [], [10_000.0]

        def wait(t):
            waits.append(t)
            clock[0] += 60
            if len(waits) >= turns:
                stop.set()
            return stop.is_set()
        with mock.patch.object(collectors.store, "db", side_effect=lambda: NoClose(self.c)), \
                mock.patch.object(collectors.analysis, "_gateway_ip", return_value=GW), \
                mock.patch.object(collectors.upnp, "discover", side_effect=discover), \
                mock.patch.object(collectors.upnp, "Gateway", gateway_cls), \
                mock.patch.object(collectors.time, "time", side_effect=lambda: clock[0]), \
                mock.patch.object(collectors, "log"), mock.patch.object(stop, "wait", side_effect=wait):
            collectors.upnp_loop(stop)

    def test_a_router_reboot_is_back_within_minutes(self):
        # turn 1: found and read; turn 2: the read fails (rebooting); turn 3: the search right after
        # finds nothing yet; turn 4: back - searched again a minute later, not 30 minutes later
        script = {"reads": 0, "searches": 0}

        def discover(gw):
            script["searches"] += 1
            return None if script["searches"] == 2 else DESC

        class Dev:
            def __init__(self, gw, loc):
                pass

            def read(self):
                script["reads"] += 1
                if script["reads"] == 2:
                    raise upnp.UpnpError("the router didn't answer UPnP (TimeoutError)")
                return {"rx_total": 1000 * script["reads"], "tx_total": 1}
        self.run_turns(5, discover, Dev)
        self.assertGreaterEqual(script["reads"], 3)             # read again within the five minutes
        self.assertTrue(sources.read(self.c, "upnp")["ok"])

    def test_a_failed_description_fetch_looks_again_next_turn(self):
        searches = []

        def discover(gw):
            searches.append(gw)
            return DESC

        class Flaky:
            made = 0

            def __init__(self, gw, loc):
                Flaky.made += 1
                if Flaky.made == 1:
                    raise upnp.UpnpError("the router didn't answer UPnP (TimeoutError)")

            def read(self):
                return {"rx_total": 1, "tx_total": 1}
        self.run_turns(3, discover, Flaky)
        self.assertEqual(len(searches), 2)                       # the second turn tried again

    def test_after_a_hearth_restart_a_router_that_worked_is_looked_for_every_minute(self):
        sources.report_ok(self.c, "upnp", now=10_000.0 - 3600)   # it worked an hour before this run
        searches = []

        def discover(gw):
            searches.append(gw)
            return None                                          # the router isn't answering yet

        self.run_turns(3, discover, None)
        self.assertEqual(len(searches), 3)                       # every turn, not once per 30 minutes
        self.assertEqual(sources.read(self.c, "upnp")["ok"], False)

    def test_a_router_that_answers_but_cant_be_read_is_failing(self):
        class Unreadable:
            def __init__(self, gw, loc):
                pass

            def read(self):
                raise upnp.UpnpError("the router's UPnP traffic counters are unreadable")
        self.run_turns(2, lambda gw: DESC, Unreadable)
        st = sources.read(self.c, "upnp")
        self.assertEqual((st["configured"], st["ok"]), (True, False))
        self.assertIn("unreadable", st["error"])

    def test_turned_off_in_config(self):
        with mock.patch.dict(collectors.CFG, {"upnp": False}), \
                mock.patch.object(collectors.store, "db", side_effect=lambda: NoClose(self.c)):
            stop = threading.Event()
            stop.set()
            collectors.upnp_loop(stop)
        self.assertFalse(sources.read(self.c, "upnp")["configured"])

    def test_a_new_gateway_is_looked_up_afresh(self):
        stop, waits = threading.Event(), []

        def wait(t):
            waits.append(t)
            if len(waits) >= 3:
                stop.set()
            return stop.is_set()
        gateways = iter(["192.168.1.254", "192.168.1.254", "192.168.8.1"])
        found = []

        def discover(gw):
            found.append(gw)
            return f"http://{gw}:5000/rootDesc.xml"

        class Dev:
            def __init__(self, gw, loc):
                self.gw = gw

            def read(self):
                return {"rx_total": 1, "tx_total": 1}
        with mock.patch.object(collectors.store, "db", side_effect=lambda: NoClose(self.c)), \
                mock.patch.object(collectors.analysis, "_gateway_ip", side_effect=lambda conn: next(gateways)), \
                mock.patch.object(collectors.upnp, "discover", side_effect=discover), \
                mock.patch.object(collectors.upnp, "Gateway", Dev), \
                mock.patch.object(stop, "wait", side_effect=wait):
            collectors.upnp_loop(stop)
        self.assertEqual(found, ["192.168.1.254", "192.168.8.1"])   # found once, then again for the new router


class RetentionTest(unittest.TestCase):
    def test_wan_traffic_rolled_up_and_pruned(self):
        c = mem_db()
        self.addCleanup(c.close)
        h = int(time.time()) // 3600 * 3600 - 5 * 3600
        c.executemany("INSERT INTO traffic_wan VALUES (?,?,?,?)", [(h + 30, 100, 10, 60), (h + 90, 200, 20, 60)])
        store.rollup_hourly(c, h + 2 * 3600)
        self.assertEqual(c.execute("SELECT * FROM traffic_wan_1h").fetchall(), [(h, 300, 30)])
        old = time.time() - (store.DETAIL_DAYS + 1) * 86400
        c.execute("INSERT INTO traffic_wan VALUES (?,1,1,60)", (old,))
        store.prune(c, time.time())
        self.assertEqual(c.execute("SELECT COUNT(*) FROM traffic_wan WHERE ts < ?", (old + 1,)).fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
