"""Step 4, part 4a (#88): alerts - raised once, kept up to date, cleared after two checks without
their condition; events once; each kind switchable; the page's view and /api/status's summary."""
import http.client
import json
import sqlite3
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

from hearth import alerts, levels as lv, overview, settings, store
from hearth.web import Handler
from tests.helpers import mem_db

ON = {"alert_attention": True, "alert_outages": True, "alert_calls": False}


class Base(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)
        self.toggles = dict(ON)
        p = mock.patch.object(settings, "value", side_effect=lambda k: self.toggles.get(k))
        p.start()
        self.addCleanup(p.stop)
        self.items = []
        p = mock.patch.object(overview, "attention", side_effect=lambda conn, now: list(self.items))
        p.start()
        self.addCleanup(p.stop)
        self.now = time.time()

    def check(self, dt=30):
        self.now += dt
        alerts.run(self.c, self.now)
        return alerts.view(self.c, self.now)


class StateAlertTest(Base):
    def test_raised_once_kept_up_to_date_cleared_after_two_checks(self):
        self.items = [{"level": lv.WARN, "text": "This computer: memory 3.5 GB", "tab": "system", "item": None}]
        v = self.check()
        self.assertEqual(len(v["active"]), 1)
        self.items = [{"level": lv.BAD, "text": "This computer: memory 3.9 GB", "tab": "system", "item": None}]
        v = self.check()
        self.assertEqual(len(v["active"]), 1)                                 # same problem, new figure: one alert
        self.assertEqual((v["active"][0]["level"], v["active"][0]["text"]), (lv.BAD, "This computer: memory 3.9 GB"))
        self.items = []
        self.assertEqual(len(self.check()["active"]), 1)                     # gone once: still up (hysteresis)
        v = self.check()
        self.assertEqual((len(v["active"]), len(v["recent"])), (0, 1))      # gone twice: cleared

    def test_a_flap_is_one_alert(self):
        item = {"level": lv.BAD, "text": "Office is off the mesh", "tab": "network", "item": "unit:aa"}
        for present in (True, False, True, False, True):
            self.items = [item] if present else []
            self.check()
        self.assertEqual(self.c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 1)

    def test_fine_levels_dont_alert_and_toggles_work(self):
        self.items = [{"level": lv.OK, "text": "all good", "tab": "system", "item": None}]
        self.assertEqual(self.check()["active"], [])
        self.items = [{"level": lv.BAD, "text": "Office is off the mesh", "tab": "network", "item": "unit:aa"}]
        self.toggles["alert_attention"] = False
        self.assertEqual(self.check()["active"], [])

    def test_two_problems_sharing_an_item_are_two_alerts_that_each_clear(self):
        # #97: the router's health and its restart both have item "router": once one key, two open
        # rows, and an orphan that never cleared
        self.items = [{"level": lv.BAD, "text": "The router needs a look: hot (86 °C)", "tab": "system", "item": "router"},
                      {"level": lv.WARN, "text": "The router restarted in the last day (09:00)", "tab": "system", "item": "router"}]
        self.assertEqual(len(self.check()["active"]), 2)
        self.check()
        self.assertEqual(self.c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 2)
        self.items = []
        self.check()
        v = self.check()
        self.assertEqual((len(v["active"]), len(v["recent"])), (0, 2))       # both cleared, nothing orphaned

    def test_the_same_key_twice_is_one_alert_at_the_worst_level(self):
        twin = {"text": "x", "tab": "system", "item": "src:router"}
        self.items = [{**twin, "level": lv.WARN}, {**twin, "level": lv.BAD}]
        v = self.check()
        self.assertEqual([a["level"] for a in v["active"]], [lv.BAD])

    def test_one_open_row_per_key_is_enforced(self):
        self.c.execute("INSERT INTO alerts (key, level, text, first, last, kind) VALUES ('k', 'bad', 't', 1, 1, 'state')")
        with self.assertRaises(sqlite3.IntegrityError):
            self.c.execute("INSERT INTO alerts (key, level, text, first, last, kind) VALUES ('k', 'bad', 't', 2, 2, 'state')")

    def test_an_old_active_alert_isnt_cut_off_by_many_recent_ones(self):
        self.c.execute("INSERT INTO alerts (key, level, text, first, last, kind) VALUES ('old', 'bad', 'long-running', 1, 1, 'state')")
        self.c.executemany("INSERT INTO alerts (key, level, text, first, last, cleared, kind) VALUES (?, 'warn', 'e', ?, ?, ?, 'event')",
                           [(f"e{i}", self.now - i, self.now - i, self.now - i) for i in range(400)])
        v = alerts.view(self.c, self.now)
        self.assertEqual([a["text"] for a in v["active"]], ["long-running"])
        self.assertEqual(len(v["recent"]), alerts.RECENT_MAX)

    def test_worst_first(self):
        self.items = [{"level": lv.WARN, "text": "a", "tab": "system", "item": "src:upnp"},
                      {"level": lv.BAD, "text": "b", "tab": "system", "item": "src:router"}]
        self.assertEqual([a["text"] for a in self.check()["active"]], ["b", "a"])

    def test_poor_calls_when_turned_on(self):
        self.toggles["alert_calls"] = True
        with mock.patch.object(alerts.calls, "calls_kpi", return_value={"level": lv.BAD, "why": "poor for calls: x"}):
            v = self.check()
        self.assertEqual([a["key"] for a in v["active"]], ["calls|poor"])


class EventAlertTest(Base):
    def outage(self, start, end, kind="outage"):
        self.c.execute("INSERT INTO episodes (start, end, kind, level, truncated, data) VALUES (?,?,?,?,?,?)",
                       (start, end, kind, "bad", 0, json.dumps({"cause": "x", "lost_s": end - start})))

    def test_an_ended_outage_is_said_once(self):
        start = int(self.now) - 600
        self.outage(start, start + 240)
        v = self.check()
        self.assertEqual(v["active"], [])                                     # it's over: not active
        self.assertEqual([r["text"] for r in v["recent"]], ["The internet was down 4 min (your ISP or beyond)"])
        self.assertEqual((v["recent"][0]["tab"], v["recent"][0]["item"]), ("history", f"ep:{start}"))   # opens the episode
        self.check()
        self.assertEqual(self.c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 1)

    def test_old_outages_and_slow_spells_arent_announced(self):
        self.outage(int(self.now) - 3 * 3600, int(self.now) - 2 * 3600)
        self.outage(int(self.now) - 600, int(self.now) - 500, kind="slow")
        self.assertEqual(self.check()["recent"], [])


class NewDevicesTest(Base):
    def setUp(self):
        super().setUp()
        self.toggles["alert_new_devices"] = True

    def device(self, ip, mac, name=None):
        self.c.execute("INSERT OR REPLACE INTO devices (ip, mac, name, first_seen, last_seen, online) VALUES (?,?,?,?,?,1)",
                       (ip, mac, name, self.now, self.now))

    def texts(self):
        return [r["text"] for r in alerts.view(self.c, self.now)["recent"]]

    def test_the_first_run_records_the_house_quietly(self):
        self.device("192.168.1.10", "aa:00:00:00:00:01", "Telly")
        self.device("192.168.1.11", "aa:00:00:00:00:02")
        self.check()
        self.assertEqual(self.texts(), [])
        self.assertEqual(self.c.execute("SELECT COUNT(*) FROM device_macs").fetchone()[0], 2)

    def test_a_new_mac_is_said_once_and_links_to_it(self):
        self.device("192.168.1.10", "aa:00:00:00:00:01")
        self.check()
        self.device("192.168.1.20", "ac:00:00:00:00:09", "Kitchen speaker")
        v = self.check()
        self.assertEqual([r["text"] for r in v["recent"]], ["New device on your network: Kitchen speaker"])
        self.assertEqual((v["recent"][0]["tab"], v["recent"][0]["item"]), ("devices", "dev:ac:00:00:00:00:09"))
        self.check()
        self.assertEqual(len(self.texts()), 1)

    def test_a_new_address_for_a_known_mac_isnt_new(self):
        self.device("192.168.1.10", "aa:00:00:00:00:01")
        self.check()
        self.device("192.168.1.99", "AA-00-00-00-00-01")          # DHCP gave it another address
        self.check()
        self.assertEqual(self.texts(), [])

    def test_a_private_address_says_what_it_is(self):
        self.device("192.168.1.10", "aa:00:00:00:00:01")
        self.check()
        self.device("192.168.1.30", "da:68:26:5e:00:08")           # locally administered: a rotating private MAC
        self.check()
        self.assertTrue(self.texts()[0].startswith("A phone or laptop using a private address joined"))
        self.assertTrue(alerts.private_mac("da:68:26:5e:00:08"))
        self.assertFalse(alerts.private_mac("ac:00:00:00:00:09"))
        self.assertFalse(alerts.private_mac("junk"))

    def test_turned_off_records_nothing(self):
        self.toggles["alert_new_devices"] = False
        self.device("192.168.1.10", "aa:00:00:00:00:01")
        self.check()
        self.assertEqual(self.c.execute("SELECT COUNT(*) FROM device_macs").fetchone()[0], 0)


class ViewAndStatusTest(Base):
    def test_seen_and_status(self):
        self.items = [{"level": lv.BAD, "text": "Office is off the mesh", "tab": "network", "item": "unit:aa"}]
        v = self.check()
        self.assertEqual(v["unseen"], 1)
        st = alerts.status_fields(self.c, self.now)
        self.assertEqual(st, {"alerts_active": 1, "alert_latest": "Office is off the mesh", "alerts_unseen": 1})
        alerts.mark_seen(self.c)
        self.assertEqual(alerts.view(self.c, self.now)["unseen"], 0)

    def test_kept_90_days_after_clearing(self):
        self.c.execute("INSERT INTO alerts (key, level, text, first, last, cleared, kind) VALUES ('x', 'bad', 'old', ?, ?, ?, 'event')",
                       (self.now - 100 * 86400,) * 3)
        self.check()
        self.assertEqual(self.c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 0)


class SettingsTest(unittest.TestCase):
    def test_the_toggles_are_booleans(self):
        c = mem_db()
        self.addCleanup(c.close)
        settings.update(c, {"alert_calls": True}, None)
        for bad in (1, "true", None.__class__):
            with self.assertRaises(settings.Invalid):
                settings.update(c, {"alert_calls": bad}, None)


class EndpointTest(unittest.TestCase):
    def setUp(self):
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
        p = mock.patch.object(store, "db", side_effect=lambda: Kept())
        p.start()
        self.addCleanup(p.stop)
        c.execute("INSERT INTO alerts (key, level, text, first, last, kind) VALUES ('k', 'bad', 'Office is off the mesh', 1, 1, 'state')")

    def request(self, method, path, origin=True):
        port = self.srv.server_address[1]
        h = {"Content-Type": "application/json"}
        if origin:
            h["Origin"] = f"http://127.0.0.1:{port}"
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        self.addCleanup(conn.close)   # closed even when an assertion fails (#71)
        conn.request(method, path, body=b"{}" if method == "POST" else None, headers=h)
        r = conn.getresponse()
        out = (r.status, json.loads(r.read() or b"{}"))
        conn.close()
        return out

    def test_list_and_mark_seen(self):
        status, body = self.request("GET", "/api/alerts")
        self.assertEqual((status, body["unseen"], [a["text"] for a in body["active"]]), (200, 1, ["Office is off the mesh"]))
        status, body = self.request("POST", "/api/alerts/seen")
        self.assertEqual((status, body["unseen"]), (200, 0))

    def test_mark_seen_is_guarded_like_every_write(self):
        port = self.srv.server_address[1]
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        self.addCleanup(conn.close)   # closed even when an assertion fails (#71)
        conn.request("POST", "/api/alerts/seen", body=b"{}", headers={"Content-Type": "application/json",
                                                                       "Origin": "http://evil.example"})
        self.assertEqual(conn.getresponse().status, 403)
        conn.close()
        self.assertEqual(self.c.execute("SELECT seen FROM alerts").fetchone(), (0,))


if __name__ == "__main__":
    unittest.main()
