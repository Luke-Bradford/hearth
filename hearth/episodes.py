"""Episodes: lag reported the way a person would recognise it (#38, step 1, part 1).

The existing analysis finds spike clusters: seconds in which a target replied far slower than
usual or not at all, joined when under 6 s apart. Most clusters are a single queued second.
This module groups the real ones (not blips, not device-sweep noise) into episodes - an
outage, a problem, a slow spell - and counts the rest as momentary spikes. Pure functions:
no database, no clock, so every rule is tested directly.

Definitions (design, section 1):
- a *lost* second: at least half of the internet targets pinged that second got no reply,
  and at least two of them when two or more were pinged; with a single configured target,
  its loss counts alone;
- a *dark* second: every internet target pinged that second got no reply;
- an *unmeasured* second: no internet target was pinged (Hearth restarting, a stalled
  pinger). It is neither lost nor dark and breaks a run of dark seconds.
"""
from .levels import BAD as LEVEL_BAD, WARN as LEVEL_WARN  # the one set of level names

EPISODE_GAP_S = 60     # real clusters at most this far apart form one episode
OUTAGE_MIN_S = 10      # consecutive dark seconds that make an outage
PROBLEM_LOST_S = 3     # lost seconds anywhere in an episode that make it a problem
PROBLEM_MIN_S = 120    # this many seconds in clusters make a problem even with nothing lost
SLOW_MIN_S = 30        # under this many seconds in clusters, and under 3 clusters: momentary.
#                        Was 10 (#101): a week of real data gave ~26 slow spells a day, half of them one
#                        10-20 s blip with nothing lost - the Overview cried wolf. 30 s (or three clusters
#                        close together) is a slowdown a call or a game notices; shorter blips are
#                        still counted, as momentary spikes
USUAL_MIN_HOURS = 6    # complete hours needed before a "usual" spike rate is given


KIND_HOME_DOWN = "home_down"
KIND_OUTAGE = "outage"
KIND_INTERNET_DOWN = "internet_down"   # dark, and the router wasn't measured
KIND_PROBLEM = "problem"
KIND_SLOW = "slow"
KIND_ORDER = (KIND_HOME_DOWN, KIND_OUTAGE, KIND_INTERNET_DOWN, KIND_PROBLEM, KIND_SLOW)  # most severe first
KIND_NAMES = {KIND_HOME_DOWN: ("home network outage", "home network outages"),
              KIND_OUTAGE: ("outage", "outages"),
              KIND_INTERNET_DOWN: ("internet outage (router not measured)", "internet outages (router not measured)"),
              KIND_PROBLEM: ("problem", "problems"),
              KIND_SLOW: ("slow spell", "slow spells")}


def _answered_by_second(samples):
    """{int second: answered} - answered if any sample in that second got a reply."""
    out = {}
    for ts, rtt in samples:
        s = int(ts)
        out[s] = out.get(s, False) or rtt is not None
    return out


def second_states(by, inet_targets, gateway):
    """{second: (lost, dark, router)} for every second at least one internet target was pinged.
    router: True if the router answered that second, False if pinged and silent, None if it
    wasn't pinged."""
    inet = [_answered_by_second(by.get(t, [])) for t in inet_targets]
    router = _answered_by_second(by.get(gateway, []))
    single = len(inet_targets) == 1
    out = {}
    for s in set().union(*inet) if inet else set():
        pinged = [a[s] for a in inet if s in a]
        missed = pinged.count(False)
        if len(pinged) >= 2:
            lost = missed >= 2 and missed * 2 >= len(pinged)
        else:
            lost = single and missed == 1
        # dark is judged on the targets pinged that second, even if only one was: lost needs
        # two (above), so one address rate-limiting can't make lost seconds, and an outage needs
        # 10 dark seconds in a row, which any answer from the other target breaks
        out[s] = (lost, missed == len(pinged), router.get(s))
    return out


def dark_runs(states, lo, hi, bridge=0):
    """[(start, end)] runs of dark seconds in [lo, hi]. A measured second that isn't dark ends
    a run; so does a stretch of unmeasured seconds (absent from states) longer than `bridge`.
    Pings don't land in every exact second - one that times out takes a little over a second -
    so a hole of up to `bridge` unmeasured seconds between dark ones is part of the run; a
    longer gap (Hearth restarting, a stalled pinger) breaks it, so an outage is never inferred
    from missing data."""
    runs, prev = [], None   # prev: the last measured second seen
    for s in range(lo, hi + 1):
        st = states.get(s)
        if st is None:
            continue
        if st[1]:
            if runs and prev == runs[-1][1] and s - prev - 1 <= bridge:
                runs[-1][1] = s
            else:
                runs.append([s, s])
        prev = s
    return [tuple(r) for r in runs]


def _span(seconds):
    return f"{seconds // 60} min" if seconds >= 120 else f"{seconds} s"


def _group(clusters):
    """Real clusters (not blips, not sweep noise), oldest first, grouped when the gap between
    one cluster's end and the next one's start is at most EPISODE_GAP_S."""
    real = sorted((c for c in clusters if not c["blip"] and not c["during_sweep"]), key=lambda c: c["start"])
    groups = []
    for c in real:
        if groups and c["start"] - groups[-1][-1]["end"] <= EPISODE_GAP_S:  # sorted, non-overlapping
            groups[-1].append(c)
        else:
            groups.append([c])
    return groups


def _classify(group, states, single_target, bridge=0):
    """The episode a group of clusters forms, or None if it's momentary. Kinds are checked in
    the design's order, most severe first, so the episode takes the most severe kind any
    part of it qualifies for: a qualifying dark run makes it an outage of some sort even if it
    also has lost seconds or a long slow part (mentioned in the cause)."""
    start, end = group[0]["start"], max(c["end"] for c in group)
    duration = end - start + 1   # the span, gaps included: what the episode record reports
    seconds = set()
    for c in group:
        seconds.update(range(c["start"], c["end"] + 1))
    busy = len(seconds)          # seconds actually spent in clusters: what "lasting" means in the
    #                              design ("two clusters totalling under 10 s ... momentary")
    lost = sum(1 for s in seconds if s in states and states[s][0])
    runs = [r for c in group for r in dark_runs(states, c["start"], c["end"], bridge)]
    longest = max(runs, key=lambda r: r[1] - r[0] + 1, default=None)
    run_len = longest[1] - longest[0] + 1 if longest else 0

    faults = [c["fault"] for c in group if c["confident"] and c["fault"]]
    # the most common fault; a tie goes to the one seen first, so the answer is stable
    fault = max(dict.fromkeys(faults), key=lambda f: (faults.count(f), -faults.index(f))) if faults else None
    where = fault or "Unclear where"

    if run_len >= OUTAGE_MIN_S:
        router = [states[s][2] for s in range(longest[0], longest[1] + 1) if s in states]
        pinged = [r for r in router if r is not None]
        if not pinged:
            kind, cause = KIND_INTERNET_DOWN, "No replies from the internet; Hearth can't tell whether the router is reachable"
        elif sum(pinged) * 2 >= len(pinged):
            kind, cause = KIND_OUTAGE, "Internet down; the router is reachable"
        else:
            kind = KIND_HOME_DOWN
            cause = "Lost the connection to the router" + (f" ({fault})" if fault else "")
        cause += f" for {_span(run_len)}"
        if busy - run_len >= SLOW_MIN_S:
            cause += f", slow for {_span(duration)} in all"
    elif lost >= PROBLEM_LOST_S or busy >= PROBLEM_MIN_S:
        kind = KIND_PROBLEM
        cause = f"{where}: " + (f"{lost} s of lost replies" if lost else "replies slow, nothing lost")
    elif busy >= SLOW_MIN_S or len(group) >= 3:
        kind = KIND_SLOW
        cause = f"{where}: " + (f"replies slow, {lost} s lost" if lost else "replies slow, nothing lost")
    else:
        return None

    level = LEVEL_WARN if kind == KIND_SLOW else LEVEL_BAD
    if single_target and kind in (KIND_PROBLEM, KIND_SLOW):
        level = LEVEL_WARN
    if single_target:
        cause += " (measured against one internet address only)"
    context = []
    for c in group:
        context += [x for x in c.get("context") or [] if x not in context]
    return {"start": start, "end": end, "duration_s": duration, "kind": kind, "level": level,
            "fault": fault, "cause": cause, "clusters": len(group), "lost_s": lost, "context": context,
            "parts": [{"start": c["start"], "end": c["end"], "verdict": c["verdict"]} for c in group]}


def build(clusters, states, single_target, bridge=0):
    """(episodes oldest first, number of momentary real clusters) - see the module docstring."""
    episodes, momentary = [], 0
    for group in _group(clusters):
        ep = _classify(group, states, single_target, bridge)
        if ep:
            episodes.append(ep)
        else:
            momentary += len(group)
            for c in group:
                c["momentary"] = True  # so the page can list exactly the spikes it counts
    return episodes, momentary


def breakdown(episodes):
    """"1 outage, 2 slow spells" - most severe kind first."""
    parts = []
    for kind in KIND_ORDER:
        n = sum(1 for e in episodes if e["kind"] == kind)
        if n:
            parts.append(f"{n} {KIND_NAMES[kind][0 if n == 1 else 1]}")
    return ", ".join(parts)


def worst_level(episodes):
    levels = {e["level"] for e in episodes}
    return LEVEL_BAD if LEVEL_BAD in levels else LEVEL_WARN if levels else None


def usual_per_hour(rows):
    """Median momentary spikes per hour over hours without a bad episode; None with fewer
    than USUAL_MIN_HOURS such hours (a fresh install shows the count alone)."""
    good = sorted(spikes for _, spikes, bad in rows if not bad)
    if len(good) < USUAL_MIN_HOURS:
        return None
    mid = len(good) // 2
    return good[mid] if len(good) % 2 else (good[mid - 1] + good[mid]) / 2
