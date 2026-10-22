import unittest

from hearth import episodes as E

A, B, GW = "inet:1.1.1.1", "inet:8.8.8.8", "gateway"


def samples(start, n, rtt):
    return [(start + i + 0.3, rtt) for i in range(n)]


class SecondStatesTest(unittest.TestCase):
    def test_both_targets_lost_is_lost_and_dark(self):
        by = {A: samples(100, 3, None), B: samples(100, 3, None), GW: samples(100, 3, 2.0)}
        st = E.second_states(by, [A, B], GW)
        self.assertEqual(st[101], (True, True, True))

    def test_one_of_two_losing_alone_is_not_lost(self):
        by = {A: samples(100, 3, None), B: samples(100, 3, 20.0)}
        self.assertEqual(E.second_states(by, [A, B], GW)[100], (False, False, None))

    def test_one_of_two_targets_pinged_cannot_lose_alone(self):
        # B stopped being pinged (config changed): A losing on its own isn't a lost second
        by = {A: samples(100, 3, None)}
        self.assertEqual(E.second_states(by, [A, B], GW)[100], (False, True, None))

    def test_single_configured_target_counts_alone(self):
        by = {A: samples(100, 2, None)}
        self.assertEqual(E.second_states(by, [A], GW)[100], (True, True, None))

    def test_unmeasured_seconds_are_absent(self):
        by = {A: samples(100, 2, 20.0), B: samples(100, 2, 20.0)}
        st = E.second_states(by, [A, B], GW)
        self.assertEqual(sorted(st), [100, 101])

    def test_router_silent_is_false_not_none(self):
        by = {A: samples(100, 1, None), B: samples(100, 1, None), GW: samples(100, 1, None)}
        self.assertEqual(E.second_states(by, [A, B], GW)[100], (True, True, False))

    def test_an_answer_in_the_same_second_counts(self):
        # two samples of one target in a second: answered if either answered
        by = {A: [(100.1, None), (100.6, 20.0)], B: [(100.2, None)]}
        self.assertEqual(E.second_states(by, [A, B], GW)[100], (False, False, None))


def cluster(start, end, fault="Link to the router", confident=True, blip=False, sweep=False):
    return {"start": start, "end": end, "blip": blip, "during_sweep": sweep, "confident": confident,
            "fault": fault if confident else None, "verdict": f"Fault at: {fault}", "context": []}


def states(lost=(), dark=(), router=None, measured=range(0, 2000)):
    """Synthetic second states: every second in `measured` is measured; `lost`/`dark` seconds
    as given; router answers (True), is silent (False) or isn't pinged (None) in dark seconds."""
    lost, dark = set(lost), set(dark)
    return {s: (s in lost or s in dark, s in dark, router if s in dark else True) for s in measured}


def kinds(eps):
    return [e["kind"] for e in eps]


class BuildTest(unittest.TestCase):
    def test_single_blip_is_momentary(self):
        eps, momentary = E.build([cluster(100, 100)], states(), False)
        self.assertEqual((eps, momentary), ([], 1))

    def test_ten_one_second_clusters_within_a_minute_are_one_slow_spell(self):
        cl = [cluster(100 + 7 * i, 100 + 7 * i) for i in range(10)]  # 7 s apart: separate clusters, one minute
        eps, momentary = E.build(cl, states(), False)
        self.assertEqual((kinds(eps), momentary), ([E.KIND_SLOW], 0))
        self.assertEqual(eps[0]["clusters"], 10)

    def test_a_slow_spell_lasts_slow_min_s(self):
        eps, _ = E.build([cluster(100, 99 + E.SLOW_MIN_S)], states(), False)
        self.assertEqual((kinds(eps), eps[0]["level"]), ([E.KIND_SLOW], E.LEVEL_WARN))
        self.assertIn("nothing lost", eps[0]["cause"])

    def test_three_minute_problem_with_loss(self):
        eps, _ = E.build([cluster(100, 279)], states(lost=range(150, 155)), False)
        self.assertEqual((kinds(eps), eps[0]["level"], eps[0]["lost_s"]), ([E.KIND_PROBLEM], E.LEVEL_BAD, 5))

    def test_twelve_second_outage(self):
        eps, _ = E.build([cluster(100, 111)], states(dark=range(100, 112), router=True), False)
        self.assertEqual((kinds(eps), eps[0]["level"]), ([E.KIND_OUTAGE], E.LEVEL_BAD))
        self.assertIn("Internet down; the router is reachable", eps[0]["cause"])

    def test_threshold_boundaries(self):
        under, at = 98 + E.SLOW_MIN_S, 99 + E.SLOW_MIN_S                   # SLOW_MIN_S - 1 s, and SLOW_MIN_S
        self.assertEqual(E.SLOW_MIN_S, 30)                                   # #101: a blip under 30 s isn't a slow spell
        self.assertEqual(kinds(E.build([cluster(100, under)], states(), False)[0]), [])
        self.assertEqual(kinds(E.build([cluster(100, at)], states(), False)[0]), [E.KIND_SLOW])
        self.assertEqual(kinds(E.build([cluster(100, at)], states(lost=[101, 102]), False)[0]), [E.KIND_SLOW])
        self.assertEqual(kinds(E.build([cluster(100, 109)], states(lost=[101, 102, 103]), False)[0]),
                         [E.KIND_PROBLEM])                                    # lost replies count however short
        self.assertEqual(kinds(E.build([cluster(100, 218)], states(), False)[0]), [E.KIND_SLOW])     # 119 s
        self.assertEqual(kinds(E.build([cluster(100, 219)], states(), False)[0]), [E.KIND_PROBLEM])  # 120 s
        self.assertEqual(kinds(E.build([cluster(100, 108)], states(dark=range(100, 109), router=True), False)[0]),
                         [E.KIND_PROBLEM])  # 9 dark seconds: lost, not an outage

    def test_long_spell_without_loss_is_a_problem_that_says_nothing_lost(self):
        eps, _ = E.build([cluster(100, 229)], states(), False)
        self.assertEqual(kinds(eps), [E.KIND_PROBLEM])
        self.assertIn("nothing lost", eps[0]["cause"])

    def test_unmeasured_gap_breaks_an_outage(self):
        # two 8 s dark runs with 5 unmeasured seconds between (Hearth restarting): not an outage
        measured = [s for s in range(0, 2000) if not 108 <= s < 113]
        st = states(dark=list(range(100, 108)) + list(range(113, 121)), router=True, measured=measured)
        eps, _ = E.build([cluster(100, 120)], st, False)
        self.assertEqual(kinds(eps), [E.KIND_PROBLEM])
        self.assertEqual(eps[0]["lost_s"], 16)

    def test_no_pings_at_all_is_no_episode(self):
        self.assertEqual(E.build([], {}, False), ([], 0))

    def test_single_target_caps_problem_and_slow_at_warn(self):
        eps, _ = E.build([cluster(100, 219)], states(), True)
        self.assertEqual((kinds(eps), eps[0]["level"]), ([E.KIND_PROBLEM], E.LEVEL_WARN))
        self.assertIn("one internet address only", eps[0]["cause"])
        eps, _ = E.build([cluster(100, 109)], states(lost=[101, 102, 103]), True)
        self.assertEqual(eps[0]["level"], E.LEVEL_WARN)

    def test_single_target_dark_run_stays_bad(self):
        eps, _ = E.build([cluster(100, 111)], states(dark=range(100, 112), router=True), True)
        self.assertEqual((kinds(eps), eps[0]["level"]), ([E.KIND_OUTAGE], E.LEVEL_BAD))

    def test_noise_between_clusters_does_not_bridge(self):
        cl = [cluster(100, 129), cluster(175, 175, blip=True), cluster(222, 251)]  # 93 s between real ones
        st = states(lost=[175])
        eps, _ = E.build(cl, st, False)
        self.assertEqual(len(eps), 2)
        self.assertEqual(sum(e["lost_s"] for e in eps), 0)

    def test_sweep_noise_is_ignored(self):
        self.assertEqual(E.build([cluster(100, 130, sweep=True)], states(), False), ([], 0))

    def test_router_silent_too_is_home_network_down(self):
        eps, _ = E.build([cluster(100, 111)], states(dark=range(100, 112), router=False), False)
        self.assertEqual(kinds(eps), [E.KIND_HOME_DOWN])
        self.assertIn("Lost the connection to the router", eps[0]["cause"])

    def test_router_answer_share_decides(self):
        def run(router_answers):  # 12 dark seconds; the router answers in the first `router_answers`
            st = {s: (s >= 100, s >= 100, (s - 100 < router_answers) if s >= 100 else True) for s in range(0, 112)}
            return kinds(E.build([cluster(100, 111)], st, False)[0])
        self.assertEqual(run(6), [E.KIND_OUTAGE])        # 6 of 12: at least half
        self.assertEqual(run(1), [E.KIND_HOME_DOWN])
        self.assertEqual(run(0), [E.KIND_HOME_DOWN])
        self.assertEqual(kinds(E.build([cluster(100, 111)], states(dark=range(100, 112), router=None), False)[0]),
                         [E.KIND_INTERNET_DOWN])

    def test_dark_run_inside_a_slow_spell_makes_the_episode_an_outage(self):
        eps, _ = E.build([cluster(100, 279)], states(dark=range(150, 160), router=True), False)
        self.assertEqual(kinds(eps), [E.KIND_OUTAGE])
        self.assertIn("slow", eps[0]["cause"])

    def test_short_drop_with_router_silent_blames_the_router_link(self):
        eps, _ = E.build([cluster(100, 104, fault="Link to the router")],
                         states(dark=range(100, 105), router=False), False)
        self.assertEqual(kinds(eps), [E.KIND_PROBLEM])
        self.assertIn("Link to the router", eps[0]["cause"])

    def test_two_short_clusters_are_momentary_three_are_a_slow_spell(self):
        self.assertEqual(E.build([cluster(100, 102), cluster(130, 132)], states(), False), ([], 2))
        self.assertEqual(kinds(E.build([cluster(100, 102), cluster(130, 132), cluster(160, 162)], states(), False)[0]),
                         [E.KIND_SLOW])

    def test_unclear_fault(self):
        eps, _ = E.build([cluster(100, 129, confident=False)], states(), False)
        self.assertIsNone(eps[0]["fault"])
        self.assertIn("Unclear where", eps[0]["cause"])

    def test_breakdown_and_worst_level(self):
        eps, _ = E.build([cluster(100, 111), cluster(500, 529), cluster(900, 929)],
                         states(dark=range(100, 112), router=True), False)
        self.assertEqual(E.breakdown(eps), "1 outage, 2 slow spells")
        self.assertEqual(E.worst_level(eps), E.LEVEL_BAD)
        self.assertIsNone(E.worst_level([]))


class UsualTest(unittest.TestCase):
    def test_median_of_good_hours(self):
        rows = [(h * 3600, n, 0) for h, n in enumerate([30, 35, 41, 33, 36, 34])]
        self.assertEqual(E.usual_per_hour(rows), 34.5)

    def test_bad_hours_are_left_out(self):
        rows = [(h * 3600, 35, 0) for h in range(6)] + [(99 * 3600, 400, 1)]
        self.assertEqual(E.usual_per_hour(rows), 35)

    def test_fewer_than_six_good_hours_is_unknown(self):
        self.assertIsNone(E.usual_per_hour([(h * 3600, 35, 0) for h in range(5)]))
        self.assertIsNone(E.usual_per_hour([]))


class BridgeAndBoundaryTest(unittest.TestCase):
    def test_one_second_hole_in_a_dark_run_is_bridged(self):
        # a timed-out ping takes a little over a second, so the pinger can miss a second
        st = {s: (True, True, True) for s in range(100, 112) if s != 105}
        self.assertEqual(E.dark_runs(st, 100, 111, bridge=1), [(100, 111)])
        self.assertEqual(E.dark_runs(st, 100, 111, bridge=0), [(100, 104), (106, 111)])
        everything = {s: v for s, v in states().items() if s != 105}   # second 105 unmeasured
        eps, _ = E.build([cluster(100, 111)], {**everything, **st}, False, bridge=1)
        self.assertEqual(kinds(eps), [E.KIND_OUTAGE])

    def test_longer_gap_still_breaks(self):
        st = {s: (True, True, True) for s in list(range(100, 106)) + list(range(109, 115))}  # 3 s unmeasured
        self.assertEqual(E.dark_runs(st, 100, 114, bridge=1), [(100, 105), (109, 114)])

    def test_a_measured_answer_breaks_even_with_a_bridge(self):
        st = {s: (True, True, True) for s in range(100, 112)}
        st[105] = (False, False, True)
        self.assertEqual(E.dark_runs(st, 100, 111, bridge=5), [(100, 104), (106, 111)])

    def test_ten_dark_seconds_are_an_outage(self):
        self.assertEqual(kinds(E.build([cluster(100, 109)], states(dark=range(100, 110), router=True), False)[0]),
                         [E.KIND_OUTAGE])

    def test_gap_convention_60_joins_61_does_not(self):
        # the gap is the next cluster's start minus the previous one's end (the 6 s join uses
        # the same convention), so 60 means 59 quiet seconds between them
        joined = [cluster(100, 105), cluster(165, 170)]                  # 165 - 105 = 60
        apart = [cluster(100, 105), cluster(166, 171)]                   # 61
        self.assertEqual(len(E._group(joined)), 1)
        self.assertEqual(len(E._group(apart)), 2)


class StableAnswersTest(unittest.TestCase):
    def test_fault_tie_goes_to_the_first_seen(self):
        cl = [cluster(100, 114, fault="Broadband line"), cluster(120, 134, fault="Link to the router")]
        for _ in range(5):  # set order would vary with string hashing between runs
            eps, _ = E.build([dict(c) for c in cl], states(), False)
            self.assertEqual(eps[0]["fault"], "Broadband line")

    def test_momentary_clusters_are_marked(self):
        cl = [cluster(100, 100), cluster(500, 529)]
        E.build(cl, states(), False)
        self.assertEqual([c.get("momentary", False) for c in cl], [True, False])


class ReclassifyStoredTest(unittest.TestCase):
    """#101: when SLOW_MIN_S rises, stored slow spells that no longer qualify go, once."""

    def test_short_single_blips_go_and_the_rest_stay(self):
        import json
        from hearth import analysis, store
        from tests.test_router_usage import mem_db
        c = mem_db()
        self.addCleanup(c.close)

        def put(start, parts, kind="slow"):
            d = {"kind": kind, "clusters": len(parts), "parts": [{"start": a, "end": b} for a, b in parts]}
            c.execute("INSERT INTO episodes (start, end, kind, level, truncated, data) VALUES (?,?,?,?,?,?)",
                      (start, parts[-1][1], kind, "warn", 0, json.dumps(d)))
        put(1000, [(1000, 1014)])                                   # 15 s, one cluster: goes
        put(2000, [(2000, 2004), (2030, 2034)])                     # 10 s, two clusters: goes
        put(3000, [(3000, 3004), (3030, 3034), (3060, 3064)])       # three clusters: stays
        put(4000, [(4000, 4039)])                                   # 40 s: stays
        put(5000, [(5000, 5005)], kind="problem")                   # not a slow spell: untouched
        c.execute("INSERT INTO digests VALUES (1, '{}')")
        self.assertEqual(analysis.reclassify_stored_slow(c), 2)
        self.assertEqual(c.execute("SELECT COUNT(*) FROM digests").fetchone()[0], 0)   # rebuilt under the new rule
        self.assertEqual([s for (s,) in c.execute("SELECT start FROM episodes ORDER BY start")], [3000, 4000, 5000])
        self.assertEqual(store.get_state(c, analysis.SLOW_RULE_KEY), E.SLOW_MIN_S)
        put(6000, [(6000, 6009)])
        self.assertEqual(analysis.reclassify_stored_slow(c), 0)    # once per rule: done already

    def test_overlapping_parts_count_once_and_a_huge_part_is_harmless(self):
        # #101 (review of #102): busy time is merged intervals (overlaps once), never a set of every second
        import json
        from hearth import analysis, store
        from tests.test_router_usage import mem_db
        c = mem_db()
        self.addCleanup(c.close)
        store.set_state(c, analysis.SLOW_RULE_KEY, 0)

        def put(start, parts, kind="slow"):
            d = {"clusters": len(parts), "parts": [{"start": a, "end": b} for a, b in parts]}
            c.execute("INSERT INTO episodes (start, end, kind, level, truncated, data) VALUES (?,?,?,?,?,?)",
                      (start, 0, kind, "warn", 0, json.dumps(d)))
        put(1000, [(1000, 1019), (1010, 1029)])        # 20 + 20 overlapping by 10: 30 s busy, stays
        put(2000, [(2000, 2019), (2005, 2015)])        # 20 s busy, one inside the other: goes
        put(3000, [(3000, 10**12)])                    # damaged: a huge end - no memory blow-up, stays
        self.assertEqual(analysis.reclassify_stored_slow(c), 1)
        self.assertEqual([s for (s,) in c.execute("SELECT start FROM episodes ORDER BY start")], [1000, 3000])
