import time
import unittest
from unittest import mock

from hearth import analysis, mesh, store
from tests.helpers import DEVICE_LIST, LOUNGE, MAIN, OFFICE, mem_db, snapshot


class ParseQualityFieldsTest(unittest.TestCase):
    def test_backhaul_signal_and_rates_kept_only_when_plausible(self):
        rows = {"device_list": [dict(DEVICE_LIST["device_list"][0],
                                     signal_strength={"band5": -55, "band6": -58, "band2_4": -40},
                                     rx_rate_list={"band5": 1153, "band6": "1729"},
                                     tx_rate_list={"band5": 99999, "band6": 2882})]}
        n = mesh.parse_nodes(rows)[0]
        self.assertEqual(n["rssi"], {"band5": -55, "band6": -58})   # 2.4 GHz isn't in use: ignored
        self.assertEqual(n["rate_rx"], {"band5": 1153})             # a string isn't a number
        self.assertEqual(n["rate_tx"], {"band6": 2882})             # 99,999 Mb/s isn't plausible

    def test_device_kind(self):
        res = {"client_list": [
            {"mac": "AA-00-00-00-00-01", "online": True, "connection_type": "band6", "client_type": "phone"},
            {"mac": "AA-00-00-00-00-02", "online": True, "connection_type": "wired", "client_type": "other"},
            {"mac": "AA-00-00-00-00-03", "online": True, "connection_type": "wired", "client_type": "<b>x</b>"}]}
        self.assertEqual([c["kind"] for c in mesh.parse_clients(res, OFFICE)], ["phone", None, None])

    def test_which_network(self):
        # #122: the Deco's main, guest or IoT network ("interface"); anything else isn't kept
        res = {"client_list": [
            {"mac": "AA-00-00-00-00-01", "online": True, "interface": "main", "client_type": "iot_device"},
            {"mac": "AA-00-00-00-00-02", "online": True, "interface": "guest"},
            {"mac": "AA-00-00-00-00-03", "online": True, "interface": "iot"},
            {"mac": "AA-00-00-00-00-04", "online": True, "interface": "<img>"},
            {"mac": "AA-00-00-00-00-05", "online": True}]}
        out = mesh.parse_clients(res, OFFICE)
        self.assertEqual([c["network"] for c in out], ["main", "guest", "iot", None, None])
        self.assertEqual(out[0]["kind"], "iot_device")


class GradesTest(unittest.TestCase):
    def test_rssi_grade(self):
        self.assertEqual([mesh.rssi_grade(v) for v in (-50, -65, -66, -75, -76, None)],
                         ["good", "good", "fair", "fair", "poor", None])

    SAT = {"mac": OFFICE, "name": "Office", "role": "satellite", "online": True, "backhaul": "wireless",
           "bands": ["band5", "band6"], "rssi": {"band5": -56, "band6": -58}, "rate_rx": {"band5": 864, "band6": 1729}}

    def test_healthy_backhaul(self):
        self.assertEqual(mesh.backhaul_findings(self.SAT, {"band5": 1000, "band6": 1729}), [])

    def test_backhaul_problems(self):
        weak = {**self.SAT, "rssi": {"band5": -79, "band6": -82}}
        self.assertEqual(mesh.backhaul_findings(weak)[0][0], "bad")
        self.assertIn("-79 dBm", mesh.backhaul_findings(weak)[0][1])
        slow = mesh.backhaul_findings(self.SAT, {"band5": 2000})
        self.assertIn("864 Mb/s, under half its usual 2000", slow[0][1])
        only24 = {**self.SAT, "bands": ["band2_4"], "rssi": {}}
        self.assertIn("2.4 GHz only", mesh.backhaul_findings(only24)[0][1])
        self.assertEqual(mesh.backhaul_findings({**self.SAT, "online": False})[0][0], "bad")
        self.assertEqual(mesh.backhaul_findings({**self.SAT, "role": "main"}), [])

    def test_sending_rate_drop_is_found_too(self):
        sat = {**self.SAT, "rate_tx": {"band5": 400, "band6": 1729}}
        [(level, text)] = mesh.backhaul_findings(sat, {"band5": 864}, {"band5": 1000, "band6": 1729})
        self.assertEqual(level, "warn")
        self.assertIn("sending at 400 Mb/s, under half its usual 1000", text)

    def test_device_quality(self):
        node = {"p95": 30}
        s = lambda **k: {"samples": 700, "loss_pct": 0, **k}  # noqa: E731
        self.assertEqual(mesh.device_quality(s(p95=45), node)[0], "good")
        self.assertEqual(mesh.device_quality(s(p95=117), node)[0], "fair")
        self.assertEqual(mesh.device_quality(s(p95=40, loss_pct=8), node)[0], "poor")
        self.assertEqual(mesh.device_quality(s(p95=40, loss_pct=8), node, sleepy=True)[0], "sleepy")

    def test_not_measured_vs_nothing_answered(self):
        self.assertEqual(mesh.device_quality(None, {"p95": 30}), (None, "not measured yet"))
        grade, why = mesh.device_quality({"samples": 700, "loss_pct": 100, "p95": None}, {"p95": 30})
        self.assertEqual(grade, "poor")
        self.assertIn("100% lost", why)

    def test_total_loss_beats_power_saving(self):
        grade, _ = mesh.device_quality({"samples": 700, "loss_pct": 100, "p95": None}, {"p95": 30}, sleepy=True)
        self.assertEqual(grade, "poor")

    def test_no_baseline_judges_loss_only(self):
        slow_but_fine = {"samples": 700, "loss_pct": 0, "p95": 120}
        grade, why = mesh.device_quality(slow_but_fine, None)
        self.assertEqual(grade, "good")
        self.assertIn("latency isn't judged", why)
        self.assertEqual(mesh.device_quality({**slow_but_fine, "loss_pct": 3}, {})[0], "fair")


class MeshViewQualityTest(unittest.TestCase):
    def test_view_has_backhaul_findings_history_and_device_grades(self):
        c = mem_db()
        self.addCleanup(c.close)
        now = time.time()
        snap = snapshot()
        snap["ts"] = now
        for n in snap["nodes"]:
            if n["mac"] == OFFICE:
                n.update(rssi={"band5": -79, "band6": -81}, rate_rx={"band5": 300, "band6": 600})
        snap["clients"].append({"mac": "aa:00:00:00:00:09", "ip": "192.168.1.50", "node": MAIN, "link": "band6",
                                "kind": "phone", "name": "Sam's phone"})
        store.set_state(c, mesh.MESH_STATE_KEY, snap)
        c.executemany("INSERT INTO mesh_backhaul VALUES (?,?,?,?,?,?)",
                      [(now - 3600, OFFICE, "band6", -60, 1700, 2800), (now - 600, OFFICE, "band6", -81, 600, 900)])
        fake_summary = {"devices": [{"id": "dev:aa:00:00:00:00:09", "p95": 40, "loss_pct": 0, "samples": 700,
                                     "role": "branch"}]}
        analysis.clear_cache()
        def fake(conn, minutes):  # cached() keys on the function's name, so a real function
            return fake_summary
        with mock.patch.object(analysis, "summary", fake), \
                mock.patch.object(analysis, "_my_ip", return_value=None):
            v = analysis.mesh_view(c, 60)
        analysis.clear_cache()
        office = next(n for n in v["nodes"] if n["mac"] == OFFICE)
        self.assertEqual(office["grades"], {"band5": "poor", "band6": "poor"})
        self.assertEqual(v["findings"][0]["level"], "bad")
        self.assertIn(f"{OFFICE}|band6", v["history"]["series"])
        phone = next(d for d in v["devices"] if d["mac"] == "aa:00:00:00:00:09")
        self.assertEqual((phone["kind"], phone["quality"]), ("phone", "good"))
        self.assertNotIn("quality", next(d for d in v["devices"] if d["node"] == LOUNGE))  # wired: not graded


if __name__ == "__main__":
    unittest.main()
