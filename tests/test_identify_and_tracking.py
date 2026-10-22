import struct
import unittest

from hearth import analysis, identify
from hearth.collectors import PollPacer, WifiTracker, is_dfs, paths_differ
from hearth.config import EV_WIFI_BACK, EV_WIFI_CHANNEL, EV_WIFI_LOST, TARGET_GATEWAY
from hearth.naming import _useful_hostname, group_label, group_name


def _name(n):
    return b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\0"


def _rr(name_bytes, rtype, rdata):
    return name_bytes + struct.pack("!HHIH", rtype, 0x8001, 120, len(rdata)) + rdata


def mdns_response():
    """A Chromecast-style answer: PTR -> instance, TXT with fn/md, and an A record whose name
    uses DNS compression (pointer back into the packet)."""
    hdr = struct.pack("!HHHHHH", 0, 0x8400, 0, 3, 0, 0)
    ptr_owner = _name("_googlecast._tcp.local")
    instance = _name("SHIELD-Android-TV-3ba7._googlecast._tcp.local")
    ptr = _rr(ptr_owner, identify.T_PTR, instance)
    txt_items = b"".join(bytes([len(x)]) + x for x in (b"fn=SHIELD", b"md=SHIELD Android TV", b"id=3ba7"))
    txt = _rr(instance, identify.T_TXT, txt_items)
    host_off = len(hdr) + len(ptr) + len(txt)
    a_name = _name("shield-host.local")
    a = _rr(a_name, identify.T_A, bytes([192, 168, 1, 137]))
    compressed_a = _rr(struct.pack("!H", 0xC000 | host_off), identify.T_A, bytes([192, 168, 1, 137]))
    return hdr[:6] + struct.pack("!HHH", 4, 0, 0) + ptr + txt + a + compressed_a


class MdnsTest(unittest.TestCase):
    def test_query_sets_unicast_response_bit(self):
        q = identify.build_query(["_hue._tcp.local"])
        self.assertEqual(struct.unpack("!H", q[4:6])[0], 1)         # one question
        self.assertEqual(struct.unpack("!HH", q[-4:]), (identify.T_PTR, 0x8001))

    def test_parse_and_summarise_chromecast_style(self):
        recs = identify.parse_records(mdns_response())
        kinds = [t for _, t, _ in recs]
        self.assertEqual(kinds.count(identify.T_A), 2)               # including the compressed one
        self.assertEqual(recs[-1][0], "shield-host.local")
        info = identify.summarise_mdns(recs)
        self.assertEqual(info, {"friendly": "SHIELD", "model": "SHIELD Android TV"})

    def test_app_services_never_name_the_device(self):
        recs = [("_spotify-connect._tcp.local", identify.T_PTR, "Spotify Desktop Launcher._spotify-connect._tcp.local"),
                ("GamingPC.local", identify.T_A, "192.168.1.83")]
        self.assertEqual(identify.summarise_mdns(recs)["friendly"], "GamingPC")

    def test_raop_mac_prefix_and_id_hostnames(self):
        self.assertEqual(identify._instance_label("1A1903B4F220@Kitchen._raop._tcp.local"), "Kitchen")
        recs = [("e152ff8d14834ee8bc269ce5fb794fe7.local", identify.T_A, "192.168.1.253")]
        self.assertIsNone(identify.summarise_mdns(recs)["friendly"])

    def test_malformed_packet_raises_cleanly(self):
        with self.assertRaises((ValueError, struct.error, IndexError)):
            identify.parse_records(mdns_response()[:40])


class SsdpFetchSafetyTest(unittest.TestCase):
    def test_only_plain_http_on_the_answering_private_ip(self):
        ok = identify._fetchable
        self.assertTrue(ok("http://192.168.1.137:8008/ssdp/device-desc.xml", "192.168.1.137"))
        self.assertFalse(ok("http://192.168.1.200/desc.xml", "192.168.1.137"))     # another host
        self.assertFalse(ok("https://192.168.1.137/desc.xml", "192.168.1.137"))    # not plain http
        self.assertFalse(ok("http://8.8.8.8/desc.xml", "8.8.8.8"))                 # not private
        self.assertFalse(ok("http://127.0.0.1/desc.xml", "127.0.0.1"))             # loopback
        self.assertFalse(ok("http://169.254.169.254/latest", "169.254.169.254"))   # link-local / metadata

    def test_redirects_are_refused(self):
        import http.server
        import threading
        import urllib.error

        class Redirect(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "http://169.254.169.254/latest")
                self.end_headers()

            def log_message(self, *a):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), Redirect)
        threading.Thread(target=srv.handle_request, daemon=True).start()
        try:
            with self.assertRaises(urllib.error.HTTPError) as cm:
                identify._opener.open(f"http://127.0.0.1:{srv.server_port}/desc.xml", timeout=3)
            cm.exception.close()
        finally:
            srv.server_close()

    def _serve(self, handler):
        import http.server
        import threading
        srv = http.server.HTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.handle_request, daemon=True).start()
        return srv

    def test_description_is_parsed(self):
        import http.server

        class Desc(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"<root><device><friendlyName>Lounge TV</friendlyName><manufacturer>Acme</manufacturer>" \
                       b"<modelName>T1</modelName></device></root>"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        srv = self._serve(Desc)
        try:
            info = identify.fetch_description(f"http://127.0.0.1:{srv.server_port}/d.xml")
        finally:
            srv.server_close()
        self.assertEqual(info, {"friendly": "Lounge TV", "manufacturer": "Acme", "model": "T1"})

    def test_trickling_device_is_abandoned_at_the_deadline(self):
        import http.server
        import time as _t

        class Trickle(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "100000")
                self.end_headers()
                try:
                    for _ in range(30):             # one byte every 0.4 s, far longer than allowed
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        _t.sleep(0.4)
                except OSError:
                    pass

            def log_message(self, *a):
                pass

        srv = self._serve(Trickle)
        t0 = _t.monotonic()
        try:
            info = identify.fetch_description(f"http://127.0.0.1:{srv.server_port}/d.xml", total_s=1.0)
        finally:
            srv.server_close()
        self.assertIsNone(info)
        self.assertLess(_t.monotonic() - t0, 3.0)


class NamingTest(unittest.TestCase):
    def test_hostnames_that_are_ids_are_skipped(self):
        self.assertIsNone(_useful_hostname("ecb5fa1a2b3c.lan"))
        self.assertEqual(_useful_hostname("TV-Box-Pro.lan"), "TV-Box-Pro.lan")

    def test_group_named_after_closest_member(self):
        names = {"a": "Mac mini (WiFi)", "b": "Extender 1", "c": "SHIELD"}
        floors = {"a": 9.9, "b": 7.1, "c": 8.0}
        self.assertEqual(group_name({}, names, 4, ["a", "b", "c"], "branch", floors), "Branch via Extender 1 (+2)")
        self.assertEqual(group_name({"grp:4": "TV side"}, names, 4, ["a"], "branch", floors), "TV side")

    def test_group_label_reads_inside_sentences(self):
        names = {"b": "Extender 1"}
        self.assertEqual(group_label({}, names, 4, ["b"], "relay", {"b": 7.0}), "Extender 1")
        snap = {"relays": [{"group": 4, "members": ["b"]}], "roles": {"b": {"floor": 7.0}}}
        self.assertEqual(analysis.path_label(snap, {}, names), "Via Extender 1")
        link = analysis.chain(snap, set(), {}, names)[0]["link"]
        self.assertEqual(link, "Wireless/relay link to Extender 1")
        self.assertNotIn("via", link.lower().replace("wireless/relay", ""))

    def test_announced_strings_are_clipped(self):
        long = [("x._googlecast._tcp.local", identify.T_TXT, {"fn": "A" * 9000})]
        self.assertEqual(len(identify.summarise_mdns(long)["friendly"]), 80)


class LegacyNamesTest(unittest.TestCase):
    def _db(self, rows):
        import sqlite3
        from hearth import store
        c = sqlite3.connect(":memory:")
        c.executescript(store.SCHEMA)
        c.execute("ALTER TABLE devices ADD COLUMN vendor TEXT")
        c.execute("ALTER TABLE devices ADD COLUMN friendly TEXT")
        c.execute("ALTER TABLE devices ADD COLUMN model TEXT")
        c.executemany("INSERT INTO devices (ip, mac, name, first_seen, last_seen, online) VALUES (?,?,?,?,?,?)", rows)
        self.addCleanup(c.close)
        return c

    def test_newest_row_wins_and_shared_macs_are_skipped(self):
        from hearth.naming import device_names
        c = self._db([
            ("192.168.1.10", "aa:aa:aa:aa:aa:01", "old-name", 0, 100, 0),
            ("192.168.1.11", "aa:aa:aa:aa:aa:01", "new-name", 0, 900, 1),   # same MAC: shared
            ("192.168.1.20", "bb:bb:bb:bb:bb:02", "tv", 0, 900, 1),
        ])
        from hearth import store
        store.set_state(c, "shared_mac_ips", ["192.168.1.10", "192.168.1.11"])
        names = device_names(c)
        self.assertNotIn("dev:aa:aa:aa:aa:aa:01", names)            # ambiguous legacy id: no name
        self.assertEqual(names["dev:ip:192.168.1.11"], "new-name")
        self.assertEqual(names["dev:bb:bb:bb:bb:bb:02"], "tv")


class MachineNameFirstTest(unittest.TestCase):
    def _names(self, rows, router=()):
        from hearth.naming import device_names
        from tests.test_router_usage import mem_db
        c = mem_db()
        self.addCleanup(c.close)
        c.executemany("INSERT INTO devices (ip, mac, name, first_seen, last_seen, online, friendly, app_name) "
                      "VALUES (?,?,?,0,900,1,?,?)", rows)
        c.executemany("INSERT INTO router_clients VALUES (?,?,?,1,900)", router)
        return device_names(c)

    def test_hostname_beats_an_apps_upnp_name(self):
        # Acme on a PC announces "ProductAgent for Windows" over UPnP
        names = self._names([("192.168.1.228", "aa:aa:aa:aa:aa:01", "GamingPC.lan", None, "ProductAgent for Windows")])
        self.assertEqual(names["dev:aa:aa:aa:aa:aa:01"], "GamingPC.lan")

    def test_router_name_beats_upnp_name(self):
        names = self._names([("192.168.1.228", "aa:aa:aa:aa:aa:01", None, None, "ProductAgent for Windows")],
                            router=[("aa:aa:aa:aa:aa:01", "192.168.1.228", "GamingPC")])
        self.assertEqual(names["dev:aa:aa:aa:aa:aa:01"], "GamingPC")

    def test_mdns_name_beats_router_name(self):
        names = self._names([("192.168.1.161", "aa:aa:aa:aa:aa:02", "Sams-Mac-mini.lan", "Sam’s Mac mini", None)],
                            router=[("aa:aa:aa:aa:aa:02", "192.168.1.161", "Sams-Mac-mini")])
        self.assertEqual(names["dev:aa:aa:aa:aa:aa:02"], "Sam’s Mac mini")

    def test_upnp_name_used_when_nothing_better(self):
        # a TV whose reverse-DNS name is just its MAC
        names = self._names([("192.168.1.50", "aa:aa:aa:aa:aa:03", "aabbccddeeff.lan", None, "Lounge TV")])
        self.assertEqual(names["dev:aa:aa:aa:aa:aa:03"], "Lounge TV")

    def test_identify_keeps_upnp_and_mdns_names_apart(self):
        from unittest import mock
        upnp = {"192.168.1.228": {"friendly": "ProductAgent for Windows", "manufacturer": "Acme",
                                  "model": "ProductAgent1.0"},
                "192.168.1.137": {"friendly": "SHIELD (UPnP)", "manufacturer": "NVIDIA", "model": "SHIELD"}}
        mdns = {"192.168.1.137": {"friendly": "SHIELD", "model": "SHIELD Android TV"}}
        with mock.patch.object(identify, "ssdp_scan", return_value=upnp), \
                mock.patch.object(identify, "mdns_scan", return_value=mdns):
            out = identify.identify("192.168.1.60")
        self.assertEqual(out["192.168.1.228"], {"friendly": None, "app_name": "ProductAgent for Windows",
                                                "model": "Acme ProductAgent1.0"})
        self.assertEqual(out["192.168.1.137"]["friendly"], "SHIELD")
        self.assertEqual(out["192.168.1.137"]["app_name"], "SHIELD (UPnP)")

    def test_upgrade_clears_mixed_friendly_names(self):
        import os
        import sqlite3
        import tempfile
        from unittest import mock
        from hearth import store
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.addCleanup(os.remove, path)
        old = sqlite3.connect(path)
        old.execute("CREATE TABLE devices (ip TEXT PRIMARY KEY, mac TEXT, name TEXT, first_seen REAL, "
                    "last_seen REAL, online INTEGER, vendor TEXT, friendly TEXT, model TEXT)")
        old.execute("INSERT INTO devices (ip, friendly) VALUES ('192.168.1.228', 'ProductAgent for Windows')")
        old.commit()
        old.close()
        c = sqlite3.connect(path)
        self.addCleanup(c.close)
        with mock.patch.object(store, "DB_PATH", path):
            store.init_db()
            self.assertEqual(c.execute("SELECT friendly, app_name FROM devices").fetchall(), [(None, None)])
            c.execute("UPDATE devices SET friendly='GamingPC'")
            c.commit()
            store.init_db()  # a later start must not clear names again
        self.assertEqual(c.execute("SELECT friendly FROM devices").fetchone(), ("GamingPC",))


class MacOnlyNameTest(unittest.TestCase):
    def test_private_mac_says_so(self):
        from hearth import net
        from hearth.naming import fallback_name
        mac = "fe:cc:74:5e:00:0a"  # locally administered bit set: a randomised private address
        self.assertEqual(fallback_name(net.vendor(mac), mac), f"{net.PRIVATE_MAC_VENDOR} · {mac}")

    def test_unknown_maker_is_just_the_address(self):
        from hearth.naming import fallback_name
        self.assertEqual(fallback_name(None, "192.168.1.9"), "192.168.1.9")
        self.assertEqual(fallback_name("Acme Corp, Ltd", "192.168.1.9"), "Acme Corp · 192.168.1.9")

    def test_usage_names_a_private_mac(self):
        from tests.test_router_usage import mem_db
        c = mem_db()
        self.addCleanup(c.close)
        from hearth import net
        namer = analysis._usage_namer(c)
        self.assertEqual(namer("fe:cc:74:5e:00:0a"), f"{net.PRIVATE_MAC_VENDOR} · fe:cc:74:5e:00:0a")
        # malformed MACs from a router or mesh reading name as themselves, never raise
        for bad in ("zz:cc:74:a6:00:0b", "garbage"):
            self.assertEqual(namer(bad), bad)

    def test_private_mac_detection(self):
        from hearth import net
        self.assertTrue(net.is_private_mac("fe:cc:74:5e:00:0a"))
        self.assertTrue(net.is_private_mac("FE-CC-74-5E-00-0A"))
        self.assertFalse(net.is_private_mac("60:cf:84:5e:00:02"))  # a maker-assigned address
        for bad in ("", None, "zz:cc:74:a6:00:0b", "garbage"):
            self.assertFalse(net.is_private_mac(bad))

    def test_maker_lookup_accepts_dashes(self):
        from unittest import mock
        from hearth import net
        with mock.patch.object(net, "_oui", {"60CF84": "ASUSTek COMPUTER INC."}):
            self.assertEqual(net.vendor("60-cf-84-5e-00-02"), net.vendor("60:cf:84:5e:00:02"))
            self.assertEqual(net.vendor("60-cf-84-5e-00-02"), "ASUSTek COMPUTER INC.")


class PathsDifferTest(unittest.TestCase):
    def test_unanswered_hops_are_unknown_not_different(self):
        a = ["192.168.1.254", "172.16.14.218", None, "62.172.102.138", "1.1.1.1"]
        b = ["192.168.1.254", "172.16.14.218", None, None, "1.1.1.1"]
        self.assertFalse(paths_differ(a, b))

    def test_real_changes(self):
        self.assertTrue(paths_differ(["a", "b", "c"], ["a", "x", "c"]))
        self.assertTrue(paths_differ(["a", "b"], ["a", "b", "c"]))


def radio(ssid, band, ch, sig=85):
    return {"ssid": ssid, "band": band, "channel": ch, "signal": sig}


class WifiTrackerTest(unittest.TestCase):
    def test_one_hidden_radio_missing_is_not_an_event(self):
        t = WifiTracker()
        both = [(radio("Home", "5 GHz", 36), "m1", "Extender"), (radio("", "5 GHz", 36), "m1", "Extender")]
        t.update(both)
        for _ in range(3):
            self.assertEqual(t.update(both[:1]), [])

    def test_device_off_air_after_two_scans_then_back(self):
        t = WifiTracker()
        seen = [(radio("Home", "5 GHz", 36), "m1", "Extender")]
        t.update(seen)
        self.assertEqual(t.update([]), [])
        self.assertEqual([k for k, _ in t.update([])], [EV_WIFI_LOST])
        self.assertEqual(t.update([]), [])                          # reported once
        self.assertEqual([k for k, _ in t.update(seen)], [EV_WIFI_BACK])

    def test_weak_distant_devices_never_reported_lost(self):
        t = WifiTracker()
        t.update([(radio("Home", "5 GHz", 36, sig=25), "hub", "Hub")])
        t.update([])
        self.assertEqual(t.update([]), [])

    def test_channel_change_one_event_per_band_with_dfs_note(self):
        t = WifiTracker()
        t.update([(radio("Home", "5 GHz", 36), "hub", "Hub"), (radio("", "5 GHz", 36), "hub", "Hub")])
        ev = t.update([(radio("Home", "5 GHz", 104), "hub", "Hub"), (radio("", "5 GHz", 104), "hub", "Hub")])
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0][0], EV_WIFI_CHANNEL)
        self.assertIn("36 -> 104 (radar-shared DFS channel)", ev[0][1])
        self.assertTrue(is_dfs(100) and not is_dfs(36) and not is_dfs(149))


class PollPacerTest(unittest.TestCase):
    def test_sleepy_devices_slow_down_and_recover(self):
        p = PollPacer(5, 60)
        devices = {"phone": "192.168.1.70", "tv": "192.168.1.137"}
        t = 0.0
        for i in range(6):
            for d in p.due(devices, t):
                p.record(d, d == "tv" or i % 2 == 0, t)
            t += 5
        self.assertTrue(p.sleepy("phone"))
        self.assertFalse(p.sleepy("tv"))
        self.assertNotIn("phone", p.due(devices, t))                # waits ~a minute
        self.assertIn("phone", p.due(devices, t + 60))
        # recovery: three replies in a row while sleepy -> back to every 5 s
        for _ in range(3):
            t += 60
            p.record("phone", True, t)
        self.assertFalse(p.sleepy("phone"))
        self.assertIn("phone", p.due(devices, t + 5))

    def test_two_replies_are_not_enough_to_wake(self):
        p = PollPacer(5, 60)
        for ok in (False, False, False, False, True, True):
            p.record("phone", ok, 0)
        self.assertTrue(p.sleepy("phone"))

    def test_outage_ticks_do_not_make_devices_sleepy(self):
        p = PollPacer(5, 60)
        devices = [f"d{i}" for i in range(6)]
        for i in range(10):                                         # everything down at once
            p.record_tick([(d, False) for d in devices], i * 5)
        self.assertFalse(any(p.sleepy(d) for d in devices))
        self.assertIn("d0", p.due({d: "x" for d in devices}, 50))   # still every 5 s

    def test_forgets_devices_that_left(self):
        p = PollPacer(5, 60)
        p.record("old", False, 0)
        p.due({"new": "x"}, 1)
        self.assertNotIn("old", p.recent)


class ChainWithoutIspTest(unittest.TestCase):
    def test_internet_link_is_the_line_when_isp_edge_not_measured(self):
        present = {TARGET_GATEWAY, "inet:1.1.1.1"}
        ch = analysis.chain(None, present, {}, {})
        self.assertEqual([p["pos"] for p in ch], ["gateway", "internet"])
        self.assertEqual(ch[-1]["link"], "Broadband line / internet")


if __name__ == "__main__":
    unittest.main()
