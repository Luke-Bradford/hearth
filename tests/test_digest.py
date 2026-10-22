"""Step 4, part 7 (#88): the weekly digest - which week, what's in it, the headline, when it's
built, and where it shows."""
import json
import time
import unittest
from unittest import mock

from hearth import analysis, digest
from hearth.config import inet_target
from tests.helpers import mem_db

INET = inet_target("1.1.1.1")
# Wednesday 21 October 2026, noon local time
WED = time.mktime((2026, 10, 21, 12, 0, 0, 0, 0, -1))


class WeekTest(unittest.TestCase):
    def test_the_week_starts_on_monday_midnight(self):
        self.assertEqual(time.localtime(digest.week_start(WED))[:6], (2026, 10, 19, 0, 0, 0))
        self.assertEqual(time.localtime(digest.week_start(WED, 1))[:3], (2026, 10, 12))
        mon = time.mktime((2026, 10, 19, 0, 0, 1, 0, 0, -1))
        self.assertEqual(time.localtime(digest.week_start(mon))[:3], (2026, 10, 19))

    def test_a_week_across_the_clocks_going_back_is_still_monday_to_monday(self):
        # UK clocks go back on 25 October 2026: that week is 169 hours long, still Monday to Monday
        after = time.mktime((2026, 10, 27, 12, 0, 0, 0, 0, -1))
        start = digest.week_start(after, 1)
        self.assertEqual(time.localtime(start)[:4], (2026, 10, 19, 0))
        self.assertEqual(time.localtime(digest.week_start(start + 8 * 86400))[:4], (2026, 10, 26, 0))


class BuildTest(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)
        self.start = digest.week_start(WED, 1)           # Monday 12 October

    def fill(self):
        s = self.start
        self.c.executemany("INSERT INTO pings_1m (ts, target, n, lost, avg, max) VALUES (?,?,?,?,?,?)",
                           [(s + 60 * i, INET, 60, 0, 20.0, 30.0) for i in range(600)])          # 10 hours measured
        self.c.execute("INSERT INTO episodes (start, end, kind, level, truncated, data) VALUES (?,?,?,?,?,?)",
                       (s + 3600, s + 3600 + 600, "outage", "bad", 0, json.dumps({"cause": "x"})))
        for i in range(3):
            t = s + 86400 * 2 + 3600 * i                                                          # Wednesday
            self.c.execute("INSERT INTO episodes (start, end, kind, level, truncated, data) VALUES (?,?,?,?,?,?)",
                           (t, t + 120, "slow", "warn", 0, json.dumps({"cause": "slow"})))
        self.c.execute("INSERT INTO usage_1h VALUES (?, ?, ?, ?)", (int(s + 7200), "aa", 150e9, 10e9))
        self.c.execute("INSERT INTO alerts (key, level, text, first, last, cleared, kind) VALUES "
                       "('newdev|bb', 'warn', 'New device on your network: Speaker', ?, ?, ?, 'event')", (s + 99,) * 3)
        self.c.execute("INSERT INTO alerts (key, level, text, first, last, kind) VALUES ('attention|x', 'bad', 'x', ?, ?, 'state')",
                       (s + 50, s + 50))
        self.c.execute("INSERT INTO speedtests (ts, ended, down, up, grade) VALUES (?, ?, 43, 11, 'A')", (s + 500, s + 525))

    def test_the_week_in_figures(self):
        self.fill()
        with mock.patch.object(analysis, "_usage_namer", return_value=lambda mac: f"device {mac}"):
            d = digest.build(self.c, self.start)
        self.assertEqual((d["outages"], d["outage_minutes"], d["outage_sides"]), (1, 10.0, {"isp": 1, "home": 0, "unclear": 0}))
        self.assertEqual(d["uptime_pct"], round(100 * (1 - 600 / 36000), 3))
        self.assertEqual(d["slow_spells"], 3)
        self.assertEqual(d["slowest_day"], {"day": "Wednesday", "minutes": 6.0})
        self.assertEqual(d["latency_ms"], 20.0)
        self.assertEqual(d["usage"], {"down_gb": 150.0, "up_gb": 10.0, "source": "router", "top": {"name": "device aa", "gb": 160.0}})
        self.assertEqual(d["new_devices"], ["New device on your network: Speaker"])
        self.assertEqual(d["alerts"], 1)
        self.assertEqual(d["speedtests"], {"count": 1, "last": {"down": 43, "up": 11, "grade": "A"}})
        self.assertEqual(d["headline"], "1 outage (10 min, your ISP), 160 GB used.")

    def test_headlines(self):
        none = {"isp": 0, "home": 0, "unclear": 0}
        base = {"measured_s": 1, "outages": 0, "outage_sides": none, "outage_minutes": 0, "slow_spells": 3,
                "usage": {"source": "router", "down_gb": 200.0, "up_gb": 10.0}}
        self.assertEqual(digest.headline(base), "A quiet week: no outages, 210 GB used.")
        self.assertEqual(digest.headline({**base, "slow_spells": digest.QUIET_SLOW_SPELLS}),
                         f"No outages, but a slow week ({digest.QUIET_SLOW_SPELLS} slow spells), 210 GB used.")
        self.assertEqual(digest.headline({**base, "outages": 2, "outage_sides": {**none, "home": 2}, "outage_minutes": 4}),
                         "2 outages (4 min, your home network), 210 GB used.")
        self.assertEqual(digest.headline({**base, "outages": 2, "outage_sides": {**none, "isp": 1, "home": 1},
                                          "outage_minutes": 4, "usage": {"source": None, "down_gb": 0, "up_gb": 0}}),
                         "2 outages (4 min, mixed causes).")
        # #101: "unclear" (the router wasn't measured) isn't blamed on the ISP, as the outage log says
        self.assertEqual(digest.headline({**base, "outages": 1, "outage_sides": {**none, "unclear": 1}, "outage_minutes": 2,
                                          "usage": {"source": None}}), "1 outage (2 min, unclear where).")
        self.assertEqual(digest.headline({**base, "measured_s": 0}), "Hearth wasn't measuring last week.")

    def test_a_spell_across_midnight_counts_on_both_days(self):
        # #100: it went wholly to the day it started on
        tue_midnight = self.start + 86400
        self.c.execute("INSERT INTO episodes (start, end, kind, level, truncated, data) VALUES (?,?,?,?,?,?)",
                       (tue_midnight - 600, tue_midnight + 1800, "slow", "warn", 0, json.dumps({})))
        d = digest.build(self.c, self.start)
        self.assertEqual(d["slowest_day"], {"day": "Tuesday", "minutes": 30.0})   # 30 min Tuesday beats 10 Monday

    def test_a_short_outage_isnt_zero_minutes(self):
        d = {"measured_s": 1, "outages": 1, "outage_sides": {"isp": 1, "home": 0, "unclear": 0}, "outage_minutes": 0.3, "slow_spells": 0,
             "usage": {"source": None}}
        self.assertEqual(digest.headline(d), "1 outage (under a minute, your ISP).")

    def test_an_empty_week(self):
        d = digest.build(self.c, self.start)
        self.assertEqual((d["uptime_pct"], d["latency_ms"], d["usage"]["source"]), (None, None, None))
        self.assertEqual(d["headline"], "Hearth wasn't measuring last week.")


class WhenTest(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)

    def test_at_start_a_missing_last_week_is_built(self):
        self.assertEqual(digest.due(self.c, WED), digest.week_start(WED, 1))

    def test_monday_from_eight_once(self):
        digest.store_week(self.c, digest.week_start(WED, 2))       # an older one exists
        mon7 = time.mktime((2026, 10, 26, 7, 0, 0, 0, 0, -1))
        mon9 = time.mktime((2026, 10, 26, 9, 0, 0, 0, 0, -1))
        self.assertIsNone(digest.due(self.c, mon7))
        self.assertEqual(digest.due(self.c, mon9), digest.week_start(mon9, 1))
        digest.store_week(self.c, digest.week_start(mon9, 1))
        self.assertIsNone(digest.due(self.c, mon9))

    def test_kept_a_year_and_the_newest_is_shown(self):
        old = digest.week_start(WED, 60)
        self.c.execute("INSERT INTO digests VALUES (?, ?)", (int(old), json.dumps({"headline": "old"})))
        d = digest.store_week(self.c, digest.week_start(WED, 1))
        self.assertEqual(self.c.execute("SELECT COUNT(*) FROM digests").fetchone()[0], 1)
        self.assertEqual(digest.latest(self.c)["headline"], d["headline"])


if __name__ == "__main__":
    unittest.main()
