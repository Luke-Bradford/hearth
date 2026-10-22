"""Step 4, part 1 (#88): the outage log and the ISP report card (hearth/reports.py)."""
import http.client
import json
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

from hearth import analysis, levels as lv, reports, store
from hearth.config import inet_target
from hearth.web import Handler
from tests.helpers import mem_db

INET = inet_target("1.1.1.1")


def episode(c, start, end, kind, fault=None, level="bad"):
    data = {"start": start, "end": end, "kind": kind, "level": level, "cause": f"{kind} cause", "fault": fault,
            "lost_s": end - start if kind != "slow" else 0, "truncated": False}
    c.execute("INSERT INTO episodes (start, end, kind, level, truncated, data) VALUES (?,?,?,?,?,?)",
              (start, end, kind, level, 0, json.dumps(data)))


def minutes(c, start, count, avg=20.0, lost=0, n=60):
    """`count` per-minute rows for an internet target from `start` (a minute boundary)."""
    c.executemany("INSERT INTO pings_1m (ts, target, n, lost, avg, max) VALUES (?, ?, ?, ?, ?, ?)",
                  [(start + 60 * i, INET, n, lost, avg, avg * 2) for i in range(count)])


class Base(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)
        analysis.clear_cache()
        # nothing live unless a test says so: the live build is its own code, tested elsewhere
        self.live = []
        p = mock.patch.object(analysis, "cached", side_effect=lambda fn, conn, m, **k: {"episodes": self.live})
        p.start()
        self.addCleanup(p.stop)
        self.now = float(int(time.time()) // 60 * 60)


class OutagesTest(Base):
    def test_only_outages_newest_first_with_their_side(self):
        n = self.now
        episode(self.c, n - 5000, n - 4900, "outage", fault=analysis.LINK_ISP)
        episode(self.c, n - 3000, n - 2950, "home_down")
        episode(self.c, n - 2000, n - 1990, "internet_down")
        episode(self.c, n - 1000, n - 900, "slow", level="warn")          # not an outage
        out = reports.outages(self.c, 7, n)
        self.assertEqual([(o["kind"], o["side"]) for o in out["outages"]],
                         [("internet_down", "unclear"), ("home_down", "home"), ("outage", "isp")])
        self.assertEqual(out["totals"]["outage"], {"count": 1, "minutes": round(100 / 60, 1)})
        self.assertFalse(out["limited"])

    def test_uptime_leaves_out_time_hearth_wasnt_measuring(self):
        n = self.now
        minutes(self.c, n - 100 * 60, 100)                  # 100 measured minutes, nothing before
        episode(self.c, n - 50 * 60, n - 40 * 60, "outage")   # 10 of them down
        out = reports.outages(self.c, 30, n)
        self.assertEqual(out["measured_s"], 6000)
        self.assertEqual(out["uptime_pct"], 90.0)           # not 99.98% of 30 days
        self.assertEqual(out["uptime"]["level"], lv.BAD)

    def test_nothing_measured_is_unknown_not_100(self):
        out = reports.outages(self.c, 7, self.now)
        self.assertIsNone(out["uptime_pct"])
        self.assertEqual(out["uptime"]["level"], lv.UNKNOWN)

    def test_totals_cover_everything_and_are_clipped_to_the_window(self):
        n = self.now
        episode(self.c, n - 7 * 86400 - 600, n - 7 * 86400 + 600, "outage")   # half inside the 7 days
        with mock.patch.object(reports, "OUTAGE_MAX", 0):
            out = reports.outages(self.c, 7, n)
        self.assertEqual(out["outages"], [])
        self.assertTrue(out["limited"])
        self.assertEqual(out["totals"]["outage"], {"count": 1, "minutes": 10.0})

    def test_live_outages_join_unless_a_stored_one_covers_them(self):
        n = self.now
        episode(self.c, n - 1000, n - 900, "outage")
        self.live = [{"start": n - 950, "end": n - 905, "kind": "outage", "cause": "fragment"},   # overlaps: dropped
                     {"start": n - 300, "end": n - 200, "kind": "outage", "cause": "still going"},
                     {"start": n - 100, "end": n - 50, "kind": "slow", "cause": "not an outage"}]
        out = reports.outages(self.c, 7, n)
        self.assertEqual([o["cause"] for o in out["outages"]], ["still going", "outage cause"])
        self.assertEqual(out["totals"]["outage"]["count"], 2)


class MonthTest(unittest.TestCase):
    NOW = time.mktime((2026, 10, 20, 12, 0, 0, 0, 0, -1))

    def test_bounds_are_local_calendar_months(self):
        a, b = reports.month_bounds("2026-02", self.NOW)
        self.assertEqual(time.localtime(a)[:4], (2026, 2, 1, 0))
        self.assertEqual(time.localtime(b)[:4], (2026, 3, 1, 0))
        a, b = reports.month_bounds("2025-12", self.NOW)
        self.assertEqual(time.localtime(b)[:3], (2026, 1, 1))

    def test_only_this_month_and_13_before(self):
        back = lambda m: reports.months_back(m, self.NOW)   # noqa: E731
        self.assertEqual(back("2026-10"), 0)
        self.assertEqual(back("2025-09"), 13)
        for bad in ("2025-08", "2026-11", "2026-13", "2026-00", "2026-1", "26-10", "", "2026-10x", "2026-10\n"):
            self.assertIsNone(back(bad), bad)


class ReportTest(Base):
    def test_the_card(self):
        n = self.now
        start = n - 300 * 60
        minutes(self.c, start, 300, avg=20.0, lost=1, n=60)
        episode(self.c, n - 200 * 60, n - 190 * 60, "outage")                      # 10 min, ISP side
        episode(self.c, n - 100 * 60, n - 98 * 60, "home_down")                    # 2 min, home
        episode(self.c, n - 50 * 60, n - 49 * 60, "slow", fault=analysis.LINK_ISP, level="warn")
        episode(self.c, n - 40 * 60, n - 39 * 60, "slow", fault="Link to the router", level="warn")
        with mock.patch.object(reports, "month_bounds", return_value=(start, n + 3600)):
            r = reports.report(self.c, "2026-10", n)
        self.assertEqual(r["outages"]["isp"], {"count": 1, "minutes": 10.0})
        self.assertEqual(r["outages"]["home"], {"count": 1, "minutes": 2.0})
        self.assertEqual(r["slow"], {"count": 2, "minutes": 2.0, "on_line": 1})
        self.assertEqual(r["uptime_pct"], 96.0)                                    # 12 of 300 measured minutes
        self.assertEqual(r["latency"]["loss_pct"], round(100 / 60, 2))
        self.assertEqual(r["latency"]["p50_ms"], 20.0)
        self.assertFalse(r["complete"])
        self.assertFalse(r["partial"])

    def test_a_barely_measured_month_says_so(self):
        n = self.now
        minutes(self.c, n - 600, 10)
        with mock.patch.object(reports, "month_bounds", return_value=(n - 86400, n + 1)):
            r = reports.report(self.c, "2026-10", n)
        self.assertTrue(r["partial"])

    def test_worst_hour_needs_enough_minutes(self):
        n = self.now
        base = n // 3600 * 3600 - 3 * 3600    # on an hour, so the 60 minutes are one hour of the week
        minutes(self.c, base, 60, avg=20.0)
        minutes(self.c, base + 3600, 29, avg=500.0)           # too few to count
        with mock.patch.object(reports, "month_bounds", return_value=(base, n + 1)):
            r = reports.report(self.c, "2026-10", n)
        self.assertEqual(r["worst_hour"]["median_ms"], 20.0)


class HttpMixin:
    def get(self, path):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        asked = []

        def record(fn, conn, key, **kw):
            asked.append((fn.__name__, key, kw.get("ttl")))
            return {}
        with mock.patch.object(store, "db", side_effect=mem_db), mock.patch.object(analysis, "cached", side_effect=record):
            c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
            self.addCleanup(c.close)   # closed even when an assertion fails (#71)
            c.request("GET", path)
            status = c.getresponse().status
            c.close()
        return status, asked


class EndpointTest(HttpMixin, unittest.TestCase):
    def test_days_from_a_fixed_set(self):
        self.assertEqual(self.get("/api/outages?days=90"), (200, [("outages_view", 90, reports.OUTAGES_TTL_S)]))
        self.assertEqual(self.get("/api/outages")[1], [("outages_view", 30, reports.OUTAGES_TTL_S)])
        # (an empty days= is the default); %C2%B2 is "²": isdigit() says yes, int() says no (#90)
        for bad in ("8", "-7", "7.0", "1e2", "abc", "%E2%80%8B7", "%C2%B2", "%D9%A7", "%2B7", "%207"):
            self.assertEqual(self.get(f"/api/outages?days={bad}"), (400, []), bad)

    def test_month_must_be_in_range(self):
        status, asked = self.get("/api/report")
        self.assertEqual((status, asked), (200, [("report_view", 0, reports.REPORT_TTL_S)]))
        for bad in ("2026-13", "1999-01", "x", "2026-1"):
            self.assertEqual(self.get(f"/api/report?month={bad}"), (400, []), bad)


# ---------------------------------------------------------------- step 4.2: monthly usage
def hour_usage(c, ts, mac, rx, tx):
    c.execute("INSERT INTO usage_1h VALUES (?, ?, ?, ?)", (int(ts) // 3600 * 3600, mac, rx, tx))


class UsageMonthTest(unittest.TestCase):
    NOW = time.mktime((2026, 10, 20, 12, 0, 0, 0, 0, -1))

    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)

    def test_months_run_from_the_start_day(self):
        a, b = reports.usage_bounds("2026-10", self.NOW, day=15)
        self.assertEqual(time.localtime(a)[:3], (2026, 10, 15))
        self.assertEqual(time.localtime(b)[:3], (2026, 11, 15))
        self.assertIsNone(reports.usage_bounds("2026-11", self.NOW, day=15))     # hasn't begun
        self.assertIsNone(reports.usage_bounds("9999-12", self.NOW))             # #91: None, never an overflow
        self.assertIsNone(reports.usage_months_back("9999-12", self.NOW))

    def test_the_current_usage_month_turns_on_the_start_day(self):
        self.assertEqual(reports.current_usage_month(self.NOW, day=1), "2026-10")
        self.assertEqual(reports.current_usage_month(self.NOW, day=20), "2026-10")   # starts today
        self.assertEqual(reports.current_usage_month(self.NOW, day=21), "2026-09")   # not yet
        jan = time.mktime((2026, 1, 3, 12, 0, 0, 0, 0, -1))
        self.assertEqual(reports.current_usage_month(jan, day=10), "2025-12")

    def test_a_bad_start_day_is_1(self):
        for bad in (0, 29, "15", 1.5, True, None):
            with mock.patch.dict(reports.CFG, {"usage_month_starts": bad}):
                self.assertEqual(reports.month_start_day(), 1, bad)

    def test_totals_days_and_top_devices(self):
        oct2 = time.mktime((2026, 10, 2, 10, 0, 0, 0, 0, -1))
        hour_usage(self.c, oct2, "aa", 3_000, 300)
        hour_usage(self.c, oct2 + 3600, "aa", 1_000, 100)
        hour_usage(self.c, oct2 + 86400, "bb", 500, 50)
        hour_usage(self.c, time.mktime((2026, 9, 30, 10, 0, 0, 0, 0, -1)), "aa", 7, 7)   # the month before
        with mock.patch.object(reports, "USAGE_TOP", 1), \
             mock.patch.object(analysis, "_usage_namer", return_value=lambda mac: f"name {mac}"):
            u = reports.monthly_usage(self.c, "2026-10", self.NOW)
        self.assertEqual((u["source"], u["down"], u["up"]), ("router", 4_500, 450))
        self.assertEqual(u["days"], [{"date": "2026-10-02", "down": 4_000, "up": 400},
                                     {"date": "2026-10-03", "down": 500, "up": 50}])
        self.assertEqual([(d["name"], d["down"]) for d in u["devices"]], [("name aa", 4_000), ("Everything else", 500)])
        self.assertEqual(u["previous"], {"down": 7, "up": 7})
        self.assertFalse(u["complete"])

    def test_without_the_router_the_wan_counters_give_totals_only(self):
        self.c.execute("INSERT INTO traffic_wan_1h VALUES (?, ?, ?)", (int(self.NOW - 7200) // 3600 * 3600, 9_000, 900))
        u = reports.monthly_usage(self.c, "2026-10", self.NOW)
        self.assertEqual((u["source"], u["down"], u["devices"]), ("wan", 9_000, []))

    def test_nothing_read_is_said_plainly(self):
        u = reports.monthly_usage(self.c, "2026-10", self.NOW)
        self.assertEqual((u["source"], u["down"], u["days"]), (None, 0, []))

    def test_months_back_follows_usage_months(self):
        with mock.patch.dict(reports.CFG, {"usage_month_starts": 25}):
            self.assertEqual(reports.usage_months_back("2026-09", self.NOW), 0)      # September's runs to 25 Oct
            self.assertIsNone(reports.usage_months_back("2026-10", self.NOW))       # begins on the 25th
        for bad in ("2026-13", "x", "2024-01", "2026-10\n"):
            self.assertIsNone(reports.usage_months_back(bad, self.NOW), bad)

    def test_the_oldest_picker_month_is_allowed_when_the_start_day_is_ahead(self):
        # #91: on 20 October with months starting on the 25th, the current usage month is
        # September; 13 usage months back is August 2025 - 14 calendar months back, still allowed
        with mock.patch.dict(reports.CFG, {"usage_month_starts": 25}):
            self.assertEqual(reports.usage_months_back("2025-08", self.NOW), 13)
            self.assertIsNone(reports.usage_months_back("2025-07", self.NOW))      # 14 usage months back
            a, _ = reports.usage_bounds("2025-08", self.NOW)
            self.assertEqual(time.localtime(a)[:3], (2025, 8, 25))


class UsageEndpointTest(HttpMixin, unittest.TestCase):
    def test_usage_month(self):
        self.assertEqual(self.get("/api/usage/month"), (200, [("usage_month_view", 0, reports.REPORT_TTL_S)]))
        for bad in ("2026-13", "1999-01", "x"):
            self.assertEqual(self.get(f"/api/usage/month?month={bad}"), (400, []), bad)


if __name__ == "__main__":
    unittest.main()
