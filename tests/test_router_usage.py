import http.client
import json
import os
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

from hearth import analysis, collectors, router, store
from hearth.web import Handler
from tests.helpers import MAC_A, MAC_B, mem_db


class CryptTest(unittest.TestCase):
    def test_matches_openssl(self):
        # `openssl passwd -5 -salt saltstring 'Hello world!'`
        self.assertEqual(router.sha256_crypt(b"Hello world!", b"saltstring"),
                         "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5")


class ParseClientsTest(unittest.TestCase):
    def test_keeps_only_what_hearth_needs(self):
        res = {"clients": [
            {"mac": "1C:F6:4C:5E:00:01", "ip": "192.168.1.135", "name": "Mac", "online": True,
             "total_rx": "3008758003", "total_tx": "134212362", "psk": "never-copied"},
            {"mac": "", "total_rx": "1", "total_tx": "1"},              # no MAC
            {"mac": MAC_B, "total_rx": "x", "total_tx": "1"},           # junk counter
            "not a dict",
        ]}
        self.assertEqual(router.parse_clients(res), [
            {"mac": MAC_A, "ip": "192.168.1.135", "name": "Mac", "online": True,
             "rx_total": 3008758003, "tx_total": 134212362}])

    def test_unexpected_shapes(self):
        for res in (None, [], {}, {"clients": None}, {"clients": "x"}):
            self.assertEqual(router.parse_clients(res), [], res)


STATUS = {"system": {"cpu": {"temperature": 52}, "uptime": 8265.54, "load_average": [0.12, 0.04, 0.03],
                     "memory_total": 1000, "memory_free": 500, "memory_buff_cache": 150,
                     "lan_ip": "192.168.1.254", "ddns": "never-copied"},
          "wifi": [{"name": "wifi2g", "encryption": "psk2"}]}


class ParseStatusTest(unittest.TestCase):
    def test_keeps_only_health_figures(self):
        self.assertEqual(router.parse_status(STATUS),
                         {"temp_c": 52.0, "uptime_s": 8265, "load1": 0.12, "mem_used_pct": 35.0})

    def test_missing_or_junk_fields_are_none(self):
        empty = {"temp_c": None, "uptime_s": None, "load1": None, "mem_used_pct": None}
        for res in (None, [], {}, {"system": "x"}, {"system": {"cpu": {"temperature": "hot"}, "uptime": True,
                                                                 "load_average": [], "memory_total": 0}}):
            self.assertEqual(router.parse_status(res), empty, res)
        self.assertIsNone(router.parse_status({"system": {"cpu": {"temperature": 900}}})["temp_c"])  # implausible


class LinkTest(unittest.TestCase):
    """#122: the router's internet connection and traffic shaping."""

    def test_wan(self):
        self.assertEqual(router.parse_wan({"protocol": "pppoe", "status": 1, "ipv4": {"ip": "1.2.3.4"}}),
                         {"protocol": "pppoe", "connected": True, "ip": "1.2.3.4"})
        # as this router (GL.iNet MT6000, 4.x) really gives it: with its prefix length
        self.assertEqual(router.parse_wan({"protocol": "pppoe", "ipv4": {"ip": "1.2.3.4/32"}})["ip"], "1.2.3.4")
        # a private or CGNAT address means another router is in front: connected, but no internet address shown
        self.assertEqual(router.parse_wan({"protocol": "dhcp", "ipv4": {"ip": "100.64.1.2"}})["ip"], None)
        self.assertEqual(router.parse_wan({"protocol": "dhcp", "ipv4": {"ip": ""}}),
                         {"protocol": "dhcp", "connected": False, "ip": None})
        self.assertEqual(router.parse_wan({"protocol": "<b>x</b>", "ipv4": "junk"})["protocol"], None)
        self.assertIsNone(router.parse_wan([]))

    def test_sqm(self):
        self.assertEqual(router.parse_sqm({"enable": True, "download": 45, "upload": 9, "qdisc": "cake", "autorate": False}),
                         {"enabled": True, "down_mbps": 45.0, "up_mbps": 9.0, "qdisc": "cake", "autorate": False})
        self.assertEqual(router.parse_sqm({"enable": False, "download": "x", "qdisc": "a b"}),
                         {"enabled": False, "down_mbps": None, "up_mbps": None, "qdisc": None, "autorate": False})
        self.assertIsNone(router.parse_sqm({"download": 45}))       # no on/off: not a reading
        self.assertIsNone(router.parse_sqm(None))

    def test_a_failing_call_leaves_only_its_part_out(self):
        r = router.GlinetRouter("192.168.1.254", "unused")

        def call(module, func, params=None):
            if module == "sqm":
                raise router.RouterError("sqm.get_config failed (code -32601)")
            return {"protocol": "pppoe", "ipv4": {"ip": "1.2.3.4"}}
        with mock.patch.object(r, "call", side_effect=call):
            self.assertEqual(r.link(), {"wan": {"protocol": "pppoe", "connected": True, "ip": "1.2.3.4"}, "sqm": None})

    def test_shown_only_while_fresh_in_the_router_view_and_the_speed_test(self):
        db = mem_db()
        self.addCleanup(db.close)
        now = time.time()
        sqm = {"enabled": True, "down_mbps": 45.0, "up_mbps": 9.0, "qdisc": "cake", "autorate": False}
        store.set_state(db, router.LINK_STATE_KEY, {"wan": None, "sqm": sqm, "ts": now - 30})
        self.assertEqual(router.link_now(db, now)["sqm"], sqm)
        from hearth import speedtest
        self.assertEqual(speedtest.view(db)["shaping"], sqm)
        store.add_router_stats(db, now, {"temp_c": 50.0, "uptime_s": 100, "load1": 0.1, "mem_used_pct": 30.0})
        self.assertEqual(analysis.router_health(db, now)["link"]["sqm"], sqm)
        self.assertIsNone(router.link_now(db, now + router.LINK_MAX_AGE_S + 60))      # the router stopped being read


class RestartTest(unittest.TestCase):
    def test_boot_time_moving_later_is_a_restart(self):
        prev = {"uptime_s": 3 * 86400}
        self.assertTrue(router.restarted(prev, 1000, {"uptime_s": 60}, 1500))
        # ordinary polling: uptime grows with the clock (jitter allowed)
        self.assertFalse(router.restarted(prev, 1000, {"uptime_s": 3 * 86400 + 470}, 1500))
        # Hearth was off for a week but the router kept running
        self.assertFalse(router.restarted(prev, 1000, {"uptime_s": 10 * 86400 + 1000}, 7 * 86400 + 1000))

    def test_unknown_uptime_is_not_a_restart(self):
        self.assertFalse(router.restarted(None, 0, {"uptime_s": 60}, 100))
        self.assertFalse(router.restarted({"uptime_s": None}, 0, {"uptime_s": 60}, 100))
        self.assertFalse(router.restarted({"uptime_s": 500}, 0, {"uptime_s": None}, 100))


class CounterDeltaTest(unittest.TestCase):
    def test_new_device_only_sets_a_baseline(self):
        self.assertEqual(router.counter_deltas({}, {MAC_A: (500, 10)}), {})

    def test_normal_growth(self):
        self.assertEqual(router.counter_deltas({MAC_A: (500, 10)}, {MAC_A: (800, 15)}), {MAC_A: (300, 5)})

    def test_counter_going_backwards_rebaselines(self):
        # a GL.iNet router restored slightly older lifetime totals after an outage: booking the
        # new figure in full counted 115 GB in one reading (#33). Nothing is counted instead
        self.assertEqual(router.counter_deltas({MAC_A: (41_500_000_000, 900)}, {MAC_A: (41_470_000_000, 800)}), {})
        self.assertEqual(router.counter_deltas({MAC_A: (5000, 900)}, {MAC_A: (120, 40)}), {})

    def test_each_direction_rebaselines_on_its_own(self):
        self.assertEqual(router.counter_deltas({MAC_A: (5000, 900)}, {MAC_A: (120, 950)}), {MAC_A: (0, 50)})

    def test_idle_devices_are_left_out(self):
        self.assertEqual(router.counter_deltas({MAC_A: (5, 5)}, {MAC_A: (5, 5)}), {})


class FakeRouter(router.GlinetRouter):
    """GlinetRouter with the network replaced by a script of responses."""

    def __init__(self, password_file, responses):
        super().__init__("192.168.1.254", password_file)
        self.responses, self.sent = list(responses), []

    def _post(self, payload):
        self.sent.append(payload)
        return self.responses.pop(0)


CHALLENGE = {"result": {"alg": 5, "salt": "abcdefgh", "nonce": "n0nce", "hash-method": "sha256"}}


class GlinetRouterTest(unittest.TestCase):
    def setUp(self):
        fd, self.pw = tempfile.mkstemp()
        with os.fdopen(fd, "w") as f:
            f.write("GLINET_PASSWORD=s3cret-pass\n")
        self.addCleanup(os.remove, self.pw)

    def test_only_talks_to_a_lan_address(self):
        for host in ("8.8.8.8", "127.0.0.1", "169.254.1.1", "router.example", None):
            with self.assertRaises((router.RouterError, ValueError), msg=host):
                router.GlinetRouter(host, self.pw)

    def test_logs_in_again_when_the_session_expires(self):
        rt = FakeRouter(self.pw, [CHALLENGE, {"result": {"sid": "sid-1"}},
                                  {"error": {"code": -32000, "message": "Access denied"}},
                                  CHALLENGE, {"result": {"sid": "sid-2"}},
                                  {"result": {"clients": []}}])
        self.assertEqual(rt.clients(), [])
        self.assertEqual(rt.sent[-1]["params"][0], "sid-2")

    def test_password_never_sent_in_clear_or_put_in_errors(self):
        rt = FakeRouter(self.pw, [CHALLENGE, {"result": {"sid": "sid-1"}},
                                  {"error": {"code": -1}}, CHALLENGE, {"result": {"sid": "sid-2"}},
                                  {"error": {"code": -1}}])
        with self.assertRaises(router.RouterError) as cm:
            rt.clients()
        self.assertNotIn("s3cret", json.dumps(rt.sent))
        for secret in ("s3cret", "sid-1", "sid-2"):
            self.assertNotIn(secret, str(cm.exception))

    def test_refused_login(self):
        rt = FakeRouter(self.pw, [CHALLENGE, {"error": {"code": -32000}}])
        with self.assertRaises(router.RouterError):
            rt.clients()

    def test_non_object_replies_are_router_errors(self):
        rt = router.GlinetRouter("192.168.1.254", self.pw)
        for body in (b"[1, 2]", b'"hello"', b"<html>login</html>"):
            class Resp:
                def __init__(self, b): self.b = b
                def read(self, n): return self.b
                def __enter__(self): return self
                def __exit__(self, *a): return False
            with mock.patch.object(router._opener, "open", return_value=Resp(body)):
                with self.assertRaises(router.RouterError, msg=body):
                    rt.clients()

    def test_unreadable_password_file(self):
        with open(self.pw, "wb") as f:
            f.write(b"GLINET_PASSWORD=\xff\xfe\xfa")
        with self.assertRaises(router.RouterError):
            router.read_password(self.pw)
        with self.assertRaises(router.RouterError):
            router.read_password(self.pw + ".missing")


class RouterLoopTest(unittest.TestCase):
    """The collector loop with the router, network and database replaced by fakes."""

    def test_backs_off_logs_once_recovers_and_follows_a_new_gateway(self):
        script = [("192.168.1.254", None), ("192.168.1.254", "down"), ("192.168.1.254", "down"),
                  ("192.168.1.254", None), ("192.168.8.1", None)]
        built, logs, stop = [], [], threading.Event()
        state = {"i": 0}

        class Fake:
            def __init__(self, host, path):
                self.host = host
                built.append(host)

            def clients(self):
                gw, outcome = script[state["i"]]
                state["i"] += 1
                if state["i"] == len(script):
                    stop.set()
                if outcome:
                    raise router.RouterError("router unreachable: timeout")
                return [{"mac": MAC_A, "ip": None, "name": "Mac", "online": True,
                         "rx_total": 1000 * state["i"], "tx_total": 10}]

            def status(self):
                return router.parse_status(STATUS)

            def link(self):
                return {"wan": None, "sqm": None}   # a firmware without them: nothing recorded

            def security(self):
                return router.parse_security({})   # the same: every part None

        db = mem_db()
        self.addCleanup(db.close)
        fd, pw = tempfile.mkstemp()
        os.write(fd, b"GLINET_PASSWORD=test" + bytes([10]))   # the reader starts once a password is there
        os.close(fd)
        self.addCleanup(os.remove, pw)
        with mock.patch.object(collectors, "store", wraps=store) as st, \
                mock.patch.object(collectors.router, "GlinetRouter", Fake), \
                mock.patch.object(collectors.router, "credentials_path", return_value=pw), \
                mock.patch.object(collectors.router, "poll_interval_s", return_value=0.01), \
                mock.patch.object(collectors, "network_settings",
                                  side_effect=lambda: (script[min(state["i"], len(script) - 1)][0], None, None)), \
                mock.patch.object(collectors, "log", side_effect=lambda *a: logs.append(" ".join(map(str, a)))), \
                mock.patch.multiple(collectors, ROUTER_MIN_REFRESH_GAP_S=0, ROUTER_RETRY_S=0.01):
            st.db.return_value = db
            collectors.router_loop(stop)
        self.assertEqual(built, ["192.168.1.254", "192.168.8.1"])          # rebuilt for the new router
        self.assertEqual(sum("can't read" in m for m in logs), 1)         # one line for the outage
        self.assertEqual(sum("reading per-device traffic" in m for m in logs), 3)  # start, recovery, new router
        self.assertEqual(db.execute("SELECT COUNT(*) FROM usage").fetchone()[0], 2)
        errors = [c.args[2] for c in st.set_state.call_args_list
                  if c.args[1] == router.ERROR_STATE_KEY and c.args[2]]
        self.assertEqual(errors[0]["error"], "router unreachable: timeout")      # shown while failing
        self.assertIsNone(store.get_state(db, router.ERROR_STATE_KEY))             # cleared on recovery

    def test_records_router_health_and_its_restarts(self):
        uptimes, stop, n = [5000, 5000.5, 3, None], threading.Event(), {"i": 0, "rx": 0}

        class Fake:
            def __init__(self, host, path):
                self.host = host

            def clients(self):
                n["rx"] += 1000
                return [{"mac": MAC_A, "ip": None, "name": "Mac", "online": True, "rx_total": n["rx"], "tx_total": 1}]

            def status(self):
                i = n["i"]
                n["i"] += 1
                if i == len(uptimes) - 1:
                    stop.set()
                    raise router.RouterError("system.get_status failed (code -1)")  # never stops traffic
                return {"temp_c": 50.0 + i, "uptime_s": uptimes[i], "load1": 0.1, "mem_used_pct": 30.0}

            def security(self):   # #131: the firmware is updated after the second reading
                return router.parse_security({"dmz": {"enabled": False},
                                              "info": {"firmware_version": "4.11.0" if n["i"] <= 2 else "4.12.0"}})

            def link(self):   # #122: the line reconnects (a new address) after the second reading
                ip = "1.2.3.4" if n["i"] <= 2 else "1.2.3.5"
                return {"wan": {"protocol": "pppoe", "connected": True, "ip": ip},
                        "sqm": {"enabled": True, "down_mbps": 45.0, "up_mbps": 9.0, "qdisc": "cake", "autorate": False}}

        db = mem_db()
        self.addCleanup(db.close)
        fd, pw = tempfile.mkstemp()
        os.write(fd, b"GLINET_PASSWORD=test" + bytes([10]))   # the reader starts once a password is there
        os.close(fd)
        self.addCleanup(os.remove, pw)
        with mock.patch.object(collectors, "store", wraps=store) as st, \
                mock.patch.object(collectors.router, "GlinetRouter", Fake), \
                mock.patch.object(collectors.router, "credentials_path", return_value=pw), \
                mock.patch.object(collectors.router, "poll_interval_s", return_value=0.01), \
                mock.patch.object(collectors, "network_settings", return_value=("192.168.1.254", None, None)), \
                mock.patch.object(collectors, "log"), \
                mock.patch.multiple(collectors, ROUTER_MIN_REFRESH_GAP_S=0, ROUTER_STATUS_EVERY_S=0,
                                    ROUTER_SECURITY_EVERY_S=0):
            st.db.return_value = db
            collectors.router_loop(stop)
        temps = [r[0] for r in db.execute("SELECT temp_c FROM router_stats ORDER BY ts")]
        self.assertEqual(temps, [50.0, 51.0, 52.0])
        router_events = db.execute("SELECT ts, detail FROM events WHERE kind = ?", (collectors.EV_ROUTER,)).fetchall()
        restarts = [e for e in router_events if "restarted" in e[1]]
        self.assertEqual(len(restarts), 1)
        # #131: a firmware update is one event; the security reading is kept
        self.assertEqual([d for _, d in router_events if "firmware" in d], ["The router's firmware changed from 4.11.0 to 4.12.0"])
        self.assertIs(store.get_state(db, router.SECURITY_STATE_KEY)["dmz"], False)
        self.assertEqual(store.get_state(db, router.STATUS_STATE_KEY)["uptime_s"], 3)
        self.assertGreater(db.execute("SELECT COUNT(*) FROM usage").fetchone()[0], 0)  # traffic unaffected
        # #122: the connection and shaping are kept; a new internet address is one event
        link = store.get_state(db, router.LINK_STATE_KEY)
        self.assertEqual((link["wan"]["protocol"], link["sqm"]["down_mbps"]), ("pppoe", 45.0))
        changes = [d for (d,) in db.execute("SELECT detail FROM events WHERE kind = 'public_ip'")]
        self.assertEqual(changes, ["The internet address changed from 1.2.3.4 to 1.2.3.5 (as the router "
                                   "reports it) - the line reconnected"])

    def test_refresh_cannot_cut_the_failure_backoff_short(self):
        stop, attempts = threading.Event(), []

        class Down:
            def __init__(self, host, path):
                self.host = host

            def clients(self):
                attempts.append(time.time())
                router.REFRESH.set()  # someone keeps pressing "Refresh now"
                raise router.RouterError("router login refused (check the password file)")

        db = mem_db()
        self.addCleanup(db.close)
        fd, pw = tempfile.mkstemp()
        os.write(fd, b"GLINET_PASSWORD=test" + bytes([10]))   # the reader starts once a password is there
        os.close(fd)
        self.addCleanup(os.remove, pw)
        threading.Timer(0.5, stop.set).start()
        with mock.patch.object(collectors, "store", wraps=store) as st, \
                mock.patch.object(collectors.router, "GlinetRouter", Down), \
                mock.patch.object(collectors.router, "credentials_path", return_value=pw), \
                mock.patch.object(collectors, "network_settings", return_value=("192.168.1.254", None, None)), \
                mock.patch.object(collectors, "log"), \
                mock.patch.multiple(collectors, ROUTER_MIN_REFRESH_GAP_S=0, ROUTER_RETRY_S=10):
            st.db.return_value = db
            collectors.router_loop(stop)
        router.REFRESH.clear()
        self.assertEqual(len(attempts), 1)  # no retry within the back-off despite the presses


class UsageTest(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)
        self.now = time.time()
        store.save_router_clients(self.c, self.now, [
            {"mac": MAC_A, "ip": "192.168.1.135", "name": "SAMS-MAC", "online": True, "rx_total": 0, "tx_total": 0},
            {"mac": MAC_B, "ip": "192.168.1.228", "name": "GamingPC", "online": True, "rx_total": 0, "tx_total": 0}])

    def test_hourly_totals_accumulate(self):
        store.add_usage(self.c, 7200.0, 60, {MAC_A: (100, 10)})
        store.add_usage(self.c, 7260.0, 60, {MAC_A: (50, 5)})
        self.assertEqual(self.c.execute("SELECT rx, tx FROM usage_1h WHERE mac=?", (MAC_A,)).fetchall(), [(150, 15)])

    def test_current_speeds_window_totals_and_names(self):
        mb = 1_000_000
        store.add_usage(self.c, self.now - 120, 60, {MAC_A: (30 * mb, mb)})
        store.add_usage(self.c, self.now - 60, 60, {MAC_A: (262 * mb, 2 * mb), MAC_B: (7 * mb, 0)})
        store.set_label(self.c, "dev:" + MAC_B, "Gaming PC")
        u = analysis.usage(self.c, 60)
        self.assertTrue(u["available"])
        self.assertAlmostEqual(u["current"]["down_mbps"], (262 + 7) * 8 / 60, places=1)
        top = u["current"]["devices"][0]
        self.assertEqual((top["name"], top["id"]), ("SAMS-MAC", "dev:" + MAC_A))  # router's name
        devs = {d["name"]: d for d in u["window"]["devices"]}
        self.assertEqual(devs["SAMS-MAC"]["down_bytes"], 292 * mb)
        self.assertIn("Gaming PC", devs)                                          # your label wins
        self.assertAlmostEqual(devs["SAMS-MAC"]["peak_down_mbps"], 262 * 8 / 60, places=1)
        self.assertEqual(u["window"]["down_bytes"], 299 * mb)
        self.assertAlmostEqual(u["recording_since"], self.now - 180, delta=1)  # first reading's start
        charted = sum(p[1] for p in u["series"]["points"]) * u["series"]["bucket_s"] * 1e6 / 8
        self.assertAlmostEqual(charted, 299 * mb, delta=0.01 * mb)  # chart values are rounded

    def test_chart_series_by_device_add_up_and_this_computer_is_flagged(self):
        mb = 1_000_000
        macs = [f"aa:00:00:00:00:{i:02x}" for i in range(analysis.TOP_DEVICES + 2)]
        store.add_usage(self.c, self.now - 60, 60, {m: ((i + 1) * mb, 0) for i, m in enumerate(macs)})
        with mock.patch.object(analysis, "_my_ip", return_value="192.168.1.228"):
            u = analysis.usage(self.c, 60)
        series = u["series"]["by_device"]
        self.assertEqual(len(series), analysis.TOP_DEVICES + 1)          # the top ones, then the rest
        self.assertIsNone(series[-1]["id"])
        self.assertEqual(series[0]["id"], "dev:" + macs[-1])             # busiest first
        # within a day the chart and the device list read the same rows: same busiest devices
        self.assertEqual([s["id"] for s in series[:-1]],
                         [d["id"] for d in u["window"]["devices"][:analysis.TOP_DEVICES]])
        total = sum(p[1] for s in series for p in s["points"])
        self.assertAlmostEqual(total, sum(p[1] for p in u["series"]["points"]), places=2)
        self.assertEqual(u["self_id"], "dev:" + MAC_B)                   # the router's row for our IP

    def test_no_local_ip_and_no_traffic_yet(self):
        with mock.patch.object(analysis, "_my_ip", return_value=None):
            u = analysis.usage(self.c, 60)
        self.assertIsNone(u["self_id"])
        self.assertEqual(u["series"]["by_device"], [])
        self.assertEqual(u["series"]["points"], [])
        self.assertIsNone(u["current"])

    def test_local_ip_is_cached(self):
        analysis._ip_cache.update(ts=0.0, ip=None)
        with mock.patch.object(analysis.net, "local_ip", return_value="192.168.1.60") as lip:
            self.assertEqual(analysis._my_ip(), "192.168.1.60")
            self.assertEqual(analysis._my_ip(), "192.168.1.60")
        self.assertEqual(lip.call_count, 1)
        analysis._ip_cache.update(ts=0.0, ip=None)

    def test_stale_reading_is_not_shown_as_current(self):
        store.add_usage(self.c, self.now - 3600, 60, {MAC_A: (100, 1)})
        self.assertIsNone(analysis.usage(self.c, 1440)["current"])

    def test_off_when_router_never_read(self):
        c = mem_db()
        self.addCleanup(c.close)
        self.assertEqual(analysis.usage(c, 60)["available"], False)
        st = analysis.status(c)
        self.assertIsNone(st["down_mbps"])
        self.assertIsNone(st["today_down_gb"])

    def test_router_name_used_for_devices_hearth_found(self):
        self.c.execute("INSERT INTO devices (ip, mac, name, online) VALUES (?,?,?,1)",
                       ("192.168.1.228", MAC_B.upper(), "60cf84765609.lan"))
        from hearth.naming import device_names
        self.assertEqual(device_names(self.c)["dev:" + MAC_B], "GamingPC")


class GroupShortTest(unittest.TestCase):
    def test_map_names(self):
        from hearth.naming import group_short
        names = {"a": "deco-BE9300 (+2) · .231", "b": "SHIELD"}
        floors = {"a": 3.0, "b": 9.0}
        # closest member alone - even when its own name contains "(+"
        self.assertEqual(group_short({}, names, 4, ["b", "a"], "branch", floors), "deco-BE9300 (+2) · .231")
        self.assertEqual(group_short({"grp:4": "Lounge"}, names, 4, ["a", "b"], "branch", floors), "Lounge")
        self.assertEqual(group_short({}, names, 1, ["a"], "local", floors), "This computer's segment")


class BusiestTest(unittest.TestCase):
    def test_names_whoever_was_using_the_line(self):
        rows = [(1000.0, MAC_A, 60, 262_500_000, 1_000_000),   # 35 Mb/s down over 940-1000
                (1000.0, MAC_B, 60, 75_000, 0),                # 0.01 Mb/s: not busy
                (2000.0, MAC_B, 60, 75_000_000, 0),            # outside the incident
                (9000.0, MAC_B, 7200, 900_000_000_000, 0)]     # after a 2 h gap: no use for one moment
        text = analysis.busiest_during(rows, 950, 960, {MAC_A: "Mac mini", MAC_B: "PC"}.get, max_dur=180)
        self.assertEqual(text, "Using the internet then: Mac mini 35.0 Mb/s down, 0.1 up")
        self.assertIsNone(analysis.busiest_during(rows, 5000, 5010, str, max_dur=180))
        self.assertIsNone(analysis.busiest_during(rows, 8000, 8010, str, max_dur=180))


class RefreshEndpointTest(unittest.TestCase):
    def setUp(self):
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.addCleanup(self.srv.server_close)
        self.addCleanup(self.srv.shutdown)
        router.REFRESH.clear()
        self.addCleanup(router.REFRESH.clear)

    def post(self, headers):
        conn = http.client.HTTPConnection("127.0.0.1", self.srv.server_address[1], timeout=5)
        self.addCleanup(conn.close)   # closed even when an assertion fails (#71)
        conn.request("POST", "/api/router/refresh", body="{}", headers=headers)
        status = conn.getresponse().status
        conn.close()
        return status

    def test_same_origin_json_request_wakes_the_reader(self):
        self.assertEqual(self.post({"Content-Type": "application/json"}), 200)
        self.assertTrue(router.REFRESH.is_set())

    def test_cross_site_requests_refused(self):
        port = self.srv.server_address[1]
        self.assertEqual(self.post({"Content-Type": "text/plain"}), 415)
        self.assertEqual(self.post({"Content-Type": "application/json", "Origin": "https://evil.example",
                                    "Host": f"127.0.0.1:{port}"}), 403)
        self.assertFalse(router.REFRESH.is_set())


class IntervalTest(unittest.TestCase):
    def test_minimum_and_bad_values(self):
        with mock.patch.dict(router.CFG, {"router_poll_interval_s": 1}):
            self.assertEqual(router.poll_interval_s(), router.MIN_INTERVAL_S)
        with mock.patch.dict(router.CFG, {"router_poll_interval_s": "often"}):
            self.assertEqual(router.poll_interval_s(), 60.0)
        with mock.patch.dict(router.CFG, {"router_poll_interval_s": 300}):
            self.assertEqual(router.poll_interval_s(), 300.0)


if __name__ == "__main__":
    unittest.main()
