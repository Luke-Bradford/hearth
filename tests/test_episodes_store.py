"""Part 1 of step 2: slowdowns and outages kept (#64) - stored once final, read for long ranges."""
import json
import sqlite3
import time
import unittest
from unittest import mock

from hearth import analysis, collectors, episodes as ep, store
from tests.helpers import mem_db

NOW = float(int(time.time()) // 3600 * 3600 + 1800)    # half past an hour: B is well defined
B = int((NOW - analysis.LIVE_S) // 3600 * 3600)
GAP = ep.EPISODE_GAP_S


def add_pings(c, start, end, dark=()):
    """A second-by-second record of the router and both internet targets over [start, end);
    the internet targets go dark (no reply) in each (lo, hi) of `dark`, the router keeps
    answering - an outage of the internet, measured throughout."""
    rows = []
    for s in range(int(start), int(end)):
        lost = any(lo <= s < hi for lo, hi in dark)
        for tgt in ("inet:1.1.1.1", "inet:8.8.8.8"):
            rows.append((s + 0.2, tgt, None if lost else 18.0))
        rows.append((s + 0.1, "gateway", 2.0))
    c.executemany("INSERT INTO pings VALUES (?,?,?)", rows)


def at(now):
    """analysis's clock (only analysis's), fixed at `now`."""
    return mock.patch.object(analysis, "time", mock.Mock(wraps=time, time=mock.Mock(return_value=now)))


def stored(c):
    return [(s, e, t) for s, e, t in c.execute("SELECT start, end, truncated FROM episodes ORDER BY start")]


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)
        analysis.clear_cache()

    def test_only_final_episodes_are_stored_and_repeats_change_nothing(self):
        old = int(NOW) - 3 * 3600
        add_pings(self.c, old - 300, old + 300, dark=[(old, old + 20)])
        fresh = int(NOW) - 60                                   # ended under EPISODE_FINAL_S ago
        add_pings(self.c, fresh - 300, int(NOW), dark=[(fresh - 20, fresh)])
        self.assertEqual(analysis.store_episodes(self.c, NOW), 1)
        rows = stored(self.c)
        self.assertEqual(len(rows), 1)
        self.assertLessEqual(abs(rows[0][0] - old), 2)
        self.assertEqual(rows[0][2], 0)
        analysis.store_episodes(self.c, NOW)                    # again: the same single record
        self.assertEqual(stored(self.c), rows)
        data = json.loads(self.c.execute("SELECT data FROM episodes").fetchone()[0])
        self.assertEqual((data["kind"], data["truncated"]), ("outage", False))

    def test_episode_at_the_raw_window_start_is_truncated_and_kept_as_first_seen(self):
        lo = NOW - analysis.usual_window_s()
        s0 = int(lo) + 5                                         # began (as far as raw data shows) at the edge
        add_pings(self.c, int(lo), s0 + 300, dark=[(int(lo), s0 + 25)])
        analysis.store_episodes(self.c, NOW)
        first = stored(self.c)
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0][2], 1)                         # truncated
        # 15 s later the window has slid: the same outage looks shorter; the first record stands
        analysis.store_episodes(self.c, NOW + 15)
        self.assertEqual(stored(self.c), first)

    def test_a_complete_episode_replaces_a_truncated_record_of_itself(self):
        old = int(NOW) - 3 * 3600
        add_pings(self.c, old - 300, old + 300, dark=[(old, old + 20)])
        self.c.execute("INSERT INTO episodes VALUES (?,?,?,?,?,?)",
                       (old + 10, old + 19, "outage", "bad", 1, json.dumps({"start": old + 10})))
        analysis.store_episodes(self.c, NOW)
        rows = stored(self.c)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][2], 0)
        self.assertLess(rows[0][0], old + 10)

    def test_a_complete_view_never_replaces_a_longer_record(self):
        old = int(NOW) - 3 * 3600
        add_pings(self.c, old - 300, old + 300, dark=[(old, old + 20)])
        longer = (old - 100, old + 19, "outage", "bad", 1, json.dumps({"start": old - 100}))
        self.c.execute("INSERT INTO episodes VALUES (?,?,?,?,?,?)", longer)
        analysis.store_episodes(self.c, NOW)
        self.assertEqual(stored(self.c), [(old - 100, old + 19, 1)])

    def test_stored_episodes_never_overlap(self):
        for k in range(3):
            t = int(NOW) - (k + 2) * 3600
            add_pings(self.c, t - 200, t + 200, dark=[(t, t + 15)])
        for when in (NOW, NOW + 300, NOW + 600):
            analysis.store_episodes(self.c, when)
        rows = stored(self.c)
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(a[1] < b[0] for a, b in zip(rows, rows[1:])))


class ReadTest(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)
        analysis.clear_cache()
        p = mock.patch.object(analysis, "HEARTH_STARTED", 0.0)
        p.start()
        self.addCleanup(p.stop)
        store.set_state(self.c, analysis.EPISODES_STORE_KEY, {"last_ok": NOW, "last_error": None, "since": None})

    def incidents(self, minutes):
        with at(NOW):
            return analysis.incidents(self.c, minutes)

    def test_an_episode_ending_inside_the_seam_is_counted_once(self):
        # stored, ending just after B - GAP: the live build sees its last clusters as a fragment
        start, end = B - GAP - 40, B - GAP + 20
        add_pings(self.c, start - 300, B + 600, dark=[(start, end)])
        add_pings(self.c, B + 600, int(NOW))
        analysis.store_episodes(self.c, NOW)
        self.assertEqual(len(stored(self.c)), 1)
        out = self.incidents(12 * 60)
        self.assertEqual(out["episode_total"], 1)
        self.assertEqual(len(out["episodes"]), 1)
        self.assertEqual(out["episode_breakdown"], "1 outage")
        self.assertFalse(out["episodes"][0]["truncated"])

    def test_an_episode_starting_exactly_at_b_is_counted_once(self):
        add_pings(self.c, B - 600, int(NOW), dark=[(B, B + 20)])
        analysis.store_episodes(self.c, NOW)
        out = self.incidents(12 * 60)
        self.assertEqual(out["episode_total"], 1)

    def test_an_outage_still_going_on_from_before_b_is_shown(self):
        add_pings(self.c, B - 3600, int(NOW), dark=[(B - 1800, int(NOW))])
        analysis.store_episodes(self.c, NOW)                     # not final: nothing stored
        self.assertEqual(stored(self.c), [])
        out = self.incidents(12 * 60)
        self.assertEqual(out["episode_total"], 1)
        self.assertTrue(out["episodes"][0]["truncated"])

    def test_old_episodes_come_from_the_store(self):
        old = B - 30 * 3600                                      # long gone from a live build's reach
        self.c.execute("INSERT INTO episodes VALUES (?,?,?,?,?,?)",
                       (old, old + 30, "outage", "bad", 0,
                        json.dumps({"start": old, "end": old + 30, "kind": "outage", "level": "bad",
                                    "cause": "Internet down", "truncated": False})))
        add_pings(self.c, B - 120, int(NOW))
        out = self.incidents(7 * 1440)
        self.assertEqual([e["start"] for e in out["episodes"]], [old])
        self.assertEqual(out["incidents_since"], B)
        self.assertTrue(out["history_complete"])

    def test_a_long_range_parses_only_the_episodes_it_lists(self):
        base = int(NOW) - 400 * 86400 + 3600                 # inside the 400-day range
        rows = [(base + i * 900, base + i * 900 + 30, "slow", "warn", 0,
                 json.dumps({"start": base + i * 900, "end": base + i * 900 + 30, "kind": "slow", "level": "warn",
                             "cause": f"episode {i}", "truncated": False})) for i in range(30000)]
        self.c.executemany("INSERT INTO episodes VALUES (?,?,?,?,?,?)", rows)
        add_pings(self.c, B - 120, int(NOW))
        real = json.loads
        with mock.patch.object(analysis.json, "loads", side_effect=real) as loads:
            t = time.perf_counter()
            out = self.incidents(400 * 1440)
            took = time.perf_counter() - t
        self.assertEqual(out["episode_total"], 30000)
        self.assertEqual(out["episode_breakdown"], "30000 slow spells")
        self.assertEqual(len(out["episodes"]), 300)
        self.assertEqual(out["episodes"][0]["cause"], "episode 29999")      # newest first, in full
        self.assertNotIn("_stored", out["episodes"][0])
        self.assertLessEqual(loads.call_count, 300 + 5)                     # not one per stored row
        self.assertLess(took, 2.0)

    def test_short_ranges_are_unchanged(self):
        add_pings(self.c, int(NOW) - 900, int(NOW), dark=[(int(NOW) - 600, int(NOW) - 580)])
        out = self.incidents(30)
        self.assertEqual(out["episode_total"], 1)
        self.assertNotIn("incidents_since", out)

    def test_spikes_count_whole_stored_hours_before_b_and_live_after(self):
        add_pings(self.c, B - 120, int(NOW))
        hours = [B - 3 * 3600, B - 2 * 3600, B - 3600]
        self.c.executemany("INSERT INTO spike_hours VALUES (?,?,0)", [(h, n) for h, n in zip(hours, (2, 3, 4))])
        since_minutes = (NOW - (B - 3 * 3600 - 1200)) / 60      # starts 20 minutes into an earlier hour
        out = self.incidents(int(since_minutes) + 1)
        self.assertEqual(out["spikes_since"], B - 3 * 3600)      # the partial first hour isn't counted
        self.assertEqual(out["spikes_hours_counted"], 3)
        self.assertEqual(out["spikes_total"], 9)

    def test_history_incomplete_until_the_store_has_run_and_when_it_keeps_failing(self):
        add_pings(self.c, B - 120, int(NOW))
        store.set_state(self.c, analysis.EPISODES_STORE_KEY, None)
        self.assertFalse(self.incidents(1440)["history_complete"])
        store.set_state(self.c, analysis.EPISODES_STORE_KEY,
                        {"last_ok": NOW - 6 * 3600, "last_error": "saving slowdowns and outages failed: x",
                         "since": NOW - 6 * 3600})
        out = self.incidents(1440)
        self.assertFalse(out["history_complete"])
        self.assertIn("failed", out["history_error"])
        with mock.patch.object(analysis, "HEARTH_STARTED", NOW - 60):   # ran, but before this start
            store.set_state(self.c, analysis.EPISODES_STORE_KEY, {"last_ok": NOW - 120})
            self.assertFalse(self.incidents(1440)["history_complete"])


class LoopAndRetentionTest(unittest.TestCase):
    def setUp(self):
        self.c = mem_db()
        self.addCleanup(self.c.close)

    def test_store_outcome_is_recorded(self):
        collectors.store_episodes_once(self.c)
        st = store.get_state(self.c, analysis.EPISODES_STORE_KEY)
        self.assertIsNotNone(st["last_ok"])
        ok_at = st["last_ok"]
        with mock.patch.object(analysis, "store_episodes", side_effect=RuntimeError("boom")), \
                mock.patch.object(collectors, "log"):
            collectors.store_episodes_once(self.c)
        st = store.get_state(self.c, analysis.EPISODES_STORE_KEY)
        self.assertEqual(st["last_ok"], ok_at)                   # the last success is kept
        self.assertIn("RuntimeError", st["last_error"])
        self.assertIsNotNone(st["since"])

    def test_an_error_on_one_episode_fails_the_whole_run(self):
        now = time.time()
        for k in range(2):
            t = int(now) - (k + 2) * 3600
            add_pings(self.c, t - 200, t + 200, dark=[(t, t + 15)])
        self.c.commit()
        real = json.dumps
        calls = {"n": 0}

        def dumps(obj, *a, **k):
            if isinstance(obj, dict) and "truncated" in obj:
                calls["n"] += 1
                if calls["n"] == 2:
                    raise ValueError("second episode won't serialise")
            return real(obj, *a, **k)
        with mock.patch.object(analysis.json, "dumps", side_effect=dumps), mock.patch.object(collectors, "log"):
            collectors.store_episodes_once(self.c)
        self.assertEqual(stored(self.c), [])                     # the first one's write was rolled back too
        self.assertIn("ValueError", store.get_state(self.c, analysis.EPISODES_STORE_KEY)["last_error"])

    def test_a_locked_database_on_failure_doesnt_escape(self):
        locked = sqlite3.OperationalError("locked")
        with mock.patch.object(analysis, "store_episodes", side_effect=locked), \
                mock.patch.object(collectors.store, "get_state", side_effect=locked), \
                mock.patch.object(collectors, "log"):
            collectors.store_episodes_once(self.c)                   # returns: the loop carries on

    def test_status_reports_history_as_a_source(self):
        src = analysis._history_source(self.c, time.time())
        self.assertEqual(set(src), {"configured", "ok", "since", "error"})
        self.assertFalse(src["ok"])

    def test_episodes_and_spike_hours_are_kept_for_the_rollup_period(self):
        now = time.time()
        keep, gone = int(now - 30 * 86400), int(now - (store.ROLLUP_DAYS + 1) * 86400)
        for t in (keep, gone):
            self.c.execute("INSERT INTO episodes VALUES (?,?,?,?,0,'{}')", (t, t + 10, "slow", "warn"))
            self.c.execute("INSERT INTO spike_hours VALUES (?,1,0)", (t // 3600 * 3600,))
        store.prune(self.c, now)
        self.assertEqual([r[0] for r in self.c.execute("SELECT start FROM episodes")], [keep])
        self.assertEqual([r[0] for r in self.c.execute("SELECT hour FROM spike_hours")], [keep // 3600 * 3600])


if __name__ == "__main__":
    unittest.main()
