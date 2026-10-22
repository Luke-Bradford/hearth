"""#131: the Security panel - ways in from the internet, and firmware."""
import time
import unittest
from unittest import mock

from hearth import analysis, collectors, levels as lv, mesh, overview, router, security, store
from tests.helpers import mem_db

# the router's replies as this GL.iNet (MT6000, firmware 4.11) gives them
RAW = {"forwards": {"res": [{"src_dport": "32400", "id": "a", "dest_ip": "192.168.1.60", "dest_port": "32400",
                             "name": "Plex", "enabled": True, "proto": "tcp udp"}]},
       "dmz": {"enabled": False},
       "wan_access": {"enable_https": False, "enable_ping": False, "enable_ssh": False, "whitelist": [], "enable_whitelist": False},
       "upnp": {"enabled": False, "rules": [], "policy_mode": "all"},
       "cloud": {"cloud_enable": False, "rtty_web": False, "rtty_ssh": False, "bindtype": "", "token_status": 0},
       "ddns": {"device_id": "x", "enable_ddns": False},
       "tailscale": {"wan_enabled": False, "enabled": False, "lan_enabled": False},
       "zerotier": {"enabled": False, "wan_enabled": False, "lan_enabled": False},
       "wireguard": {"peers": [], "server": {"status": 0, "log": "", "tunnel_ip": "10.0.0.1"}},
       "openvpn": {"status": 0, "log": ""},
       "info": {"firmware_version": "4.11.0", "firmware_date": "2026-09-24 15:49:08", "model": "mt6000", "sn": "secret"}}


class ParseTest(unittest.TestCase):
    def test_this_router(self):
        s = router.parse_security(RAW)
        self.assertEqual(s["forwards"], [{"name": "Plex", "proto": "tcp udp", "port": "32400", "to_ip": "192.168.1.60",
                                          "to_port": "32400", "enabled": True}])
        self.assertEqual({k: s[k] for k in ("dmz", "admin_https", "admin_ssh", "upnp", "cloud", "wireguard", "openvpn")},
                         dict.fromkeys(("dmz", "admin_https", "admin_ssh", "upnp", "cloud", "wireguard", "openvpn"), False))
        self.assertEqual(s["firmware"], {"version": "4.11.0", "date": "2026-09-24 15:49:08", "model": "mt6000"})
        self.assertNotIn("secret", str(s))                                   # the serial number isn't kept

    def test_odd_replies(self):
        s = router.parse_security({"dmz": {"enabled": "yes"}, "wireguard": {"server": {"status": 1}},
                                   "openvpn": {"status": True},
                                   "forwards": {"res": [{"src_dport": "80", "dest_ip": "8.8.8.8", "dest_port": "80"},
                                                        {"src_dport": "1;rm", "dest_ip": "192.168.1.2", "dest_port": "1"},
                                                        {"src_dport": "70000", "dest_ip": "192.168.1.2", "dest_port": "1"},
                                                        {"src_dport": "80", "dest_ip": "127.0.0.1", "dest_port": "80"},
                                                        {"src_dport": "80", "dest_ip": "169.254.1.1", "dest_port": "80"},
                                                        {"src_dport": "8000-8010", "dest_ip": "192.168.1.9", "proto": "x",
                                                         "name": "<script>"}]}})
        self.assertIsNone(s["dmz"])                                          # not a bool: unknown, not "on"
        self.assertIs(s["wireguard"], True)
        self.assertIsNone(s["openvpn"])
        # a rule Hearth can't read is kept as unreadable - never dropped (security review)
        self.assertEqual([f.get("unreadable", False) for f in s["forwards"]], [True] * 5 + [False])
        self.assertEqual(s["forwards"][-1], {"name": None, "proto": "tcp", "port": "8000-8010", "to_ip": "192.168.1.9",
                                             "to_port": "8000-8010", "enabled": True})
        self.assertIsNone(s["firmware"])
        self.assertEqual(router.parse_security({})["forwards"], None)         # not read at all


class ViewTest(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)
        self.now = time.time()
        self.c.execute("INSERT INTO devices (ip, mac, name, first_seen, last_seen, online, friendly) VALUES "
                       "('192.168.1.60', 'aa:00:00:00:00:60', 'server', 0, 0, 1, 'HomeServer')")
        p = mock.patch.object(analysis, "_my_ip", return_value="192.168.1.5")   # Hearth's computer, in these tests
        p.start()
        self.addCleanup(p.stop)

    def put(self, **changes):
        s = router.parse_security({**RAW, **changes})
        store.set_state(self.c, router.SECURITY_STATE_KEY, {**s, "ts": self.now})
        analysis.clear_cache()   # attention reads the cached view (#133)

    def test_this_home(self):
        self.put()
        store.set_state(self.c, mesh.MESH_STATE_KEY, {"nodes": [{"mac": "20:e1:5d:5e:00:04", "name": "Office", "firmware": "1.3.5 Build 26071712"}]})
        v = security.view(self.c, self.now)
        self.assertEqual(v["level"], lv.OK)
        self.assertEqual([(i["level"], i["text"]) for i in v["items"]], [
            (lv.UNKNOWN, "Plex: port 32400 (TCP and UDP) is open to HomeServer · 192.168.1.60."),
            (lv.OK, "Closed: DMZ, admin page, SSH, GL.iNet cloud, UPnP, Tailscale, ZeroTier, WireGuard, OpenVPN, "
                    "dynamic DNS.")])
        self.assertEqual(v["firmware"], [{"what": "Router (mt6000)", "version": "4.11.0", "date": "2026-09-24 15:49:08"},
                                         {"what": "Office (mesh)", "version": "1.3.5 Build 26071712", "date": None}])
        self.assertEqual(overview.attention(self.c, self.now), [])

    def test_risky_settings_are_worded_ranked_and_need_attention(self):
        self.put(dmz={"enabled": True}, upnp={"enabled": True},
                 forwards={"res": [{"src_dport": "22", "dest_ip": "192.168.1.77", "dest_port": "22", "name": "ssh"}]})
        v = security.view(self.c, self.now)
        self.assertEqual(v["level"], lv.BAD)
        self.assertEqual([i["key"] for i in v["items"][:3]], ["dmz", "forward", "upnp"])
        self.assertIn("which isn't on the network now - an old rule?", v["items"][1]["text"])   # nothing at .77
        texts = [i["text"] for i in overview.attention(self.c, self.now)]
        self.assertTrue(any(t.startswith("The DMZ is on") for t in texts))

    def test_the_router_and_hearth_s_own_computer_count_as_on_the_network(self):
        # live (#131): the forward's target was the computer running Hearth, which Hearth doesn't
        # list as a device - its only row was days old and offline
        self.put(forwards={"res": [{"src_dport": "1", "dest_ip": "192.168.1.5", "dest_port": "1", "name": "a"},
                                   {"src_dport": "2", "dest_ip": "192.168.1.6", "dest_port": "2", "name": "b"}]})
        store.save_router_clients(self.c, self.now, [{"mac": "bb:00:00:00:00:06", "ip": "192.168.1.6", "name": "NAS",
                                                      "online": True}])
        texts = [i["text"] for i in security.view(self.c, self.now)["items"] if i["key"] == "forward"]
        self.assertEqual(texts, ["a: port 1 (TCP) is open to this computer (the computer running Hearth) · 192.168.1.5.",
                                 "b: port 2 (TCP) is open to NAS · 192.168.1.6."])

    def test_a_known_device_that_is_off_is_noted_not_warned(self):
        # #132 review: a console switched off mustn't raise an alert every time
        self.c.execute("INSERT INTO devices (ip, mac, name, first_seen, last_seen, online, friendly) VALUES "
                       "('192.168.1.40', 'aa:00:00:00:00:40', 'xbox', 0, 0, 0, 'Xbox')")
        self.put(forwards={"res": [{"src_dport": "3074", "dest_ip": "192.168.1.40", "dest_port": "3074", "name": "Xbox Live"}]})
        [item] = [i for i in security.view(self.c, self.now)["items"] if i["key"] == "forward"]
        self.assertEqual((item["level"], item["text"]),
                         (lv.UNKNOWN, "Xbox Live: port 3074 (TCP) is open to Xbox · 192.168.1.40, which is off right now."))
        self.assertEqual(overview.attention(self.c, self.now), [])

    def test_what_can_t_be_read_is_never_counted_as_closed(self):
        # security review: a failed read isn't "closed", and unknown big ways in aren't "all fine"
        self.put(dmz=None, forwards={"res": [{"src_dport": "80,443", "dest_ip": "192.168.1.60", "name": "web"}]})
        v = security.view(self.c, self.now)
        texts = {i["key"]: (i["level"], i["text"]) for i in v["items"]}
        self.assertEqual(texts["forward"], (lv.WARN, "A port forward (web) that Hearth can't read - see the router's "
                                                     "Port Forwarding page."))
        self.assertEqual(texts["unread"], (lv.UNKNOWN, "Couldn't read from the router: DMZ."))
        self.assertNotIn("DMZ", texts["closed"][1])
        self.put(dmz=None)
        self.assertEqual(security.view(self.c, self.now)["level"], lv.UNKNOWN)       # not OK while the DMZ is unknown
        self.put(forwards=None)
        self.assertIn("port forwards", {i["key"]: i["text"] for i in security.view(self.c, self.now)["items"]}["unread"])
        self.put(tailscale=None)
        self.assertEqual(security.view(self.c, self.now)["level"], lv.OK)            # a minor unknown: still fine

    def test_no_reading_or_an_old_one(self):
        self.assertFalse(security.view(self.c, self.now)["available"])
        self.put()
        self.assertFalse(security.view(self.c, self.now + router.SECURITY_MAX_AGE_S + 60)["available"])


class RouterFirmwareTest(unittest.TestCase):
    def test_an_update_across_a_failed_read_is_still_an_event(self):
        # #133: a reading without the firmware keeps the last one, so the next good reading compares to it
        c = mem_db()
        self.addCleanup(c.close)
        readings = iter([{"info": {"firmware_version": "4.11.0"}}, {}, {"info": {"firmware_version": "4.12.0"}}])

        class Rt:
            def security(self):
                return router.parse_security({"dmz": {"enabled": False}, **next(readings)})
        for i in range(3):
            collectors._read_router_security(c, Rt(), 1000.0 + i)
        self.assertEqual([d for (d,) in c.execute("SELECT detail FROM events WHERE detail LIKE '%firmware%'")],
                         ["The router's firmware changed from 4.11.0 to 4.12.0"])
        self.assertEqual(store.get_state(c, router.SECURITY_STATE_KEY)["firmware"]["version"], "4.12.0")


class FirmwareTest(unittest.TestCase):
    def test_a_deco_update_is_an_event_and_odd_versions_are_dropped(self):
        old = {"nodes": [{"mac": "a", "name": "Office", "online": True, "firmware": "1.3.5 Build 1"}]}
        new = {"nodes": [{"mac": "a", "name": "Office", "online": True, "firmware": "1.3.6 Build 2"}]}
        self.assertEqual(collectors.mesh_changes(old, new), ["Mesh node Office's firmware changed from 1.3.5 Build 1 to 1.3.6 Build 2"])
        self.assertEqual(collectors.mesh_changes({"nodes": [{"mac": "a", "online": True}]}, new), [])   # before #131: no event
        nodes = mesh.parse_nodes({"device_list": [{"mac": "AA-00-00-00-00-01", "role": "master", "software_ver": "1.3.5 Build 2607"},
                                                  {"mac": "AA-00-00-00-00-02", "role": "slave", "software_ver": "<b>x</b>"}]})
        self.assertEqual([n["firmware"] for n in nodes], ["1.3.5 Build 2607", None])


if __name__ == "__main__":
    unittest.main()
