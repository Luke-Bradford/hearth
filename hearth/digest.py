"""Step 4, part 7 (#88): the weekly digest - last week in a few lines, with one plain headline.

Built each Monday from 08:00 local time for the week before (Monday to Monday), and at start if
last week's is missing, from what Hearth already keeps: outages and slow spells (episodes),
latency (per-minute pings), usage, new devices and alerts, and speed tests. Stored, so a past
week reads the same later. Shown on the Overview; its headline is in /api/status for Home
Assistant (delivery channels come later, #37)."""
import json
import statistics
import time

from . import analysis, reports

KEEP_WEEKS = 53
QUIET_SLOW_SPELLS = 50   # under this many slow spells in a week is quiet: about what one install saw in an
                         # ordinary week under #101's rule, so "slow week" means more than usual
BUILD_HOUR = 8


def week_start(now, weeks_back=0):
    """Local midnight on the Monday that starts the week holding `now`, `weeks_back` weeks earlier."""
    t = time.localtime(now)
    midnight = time.mktime((t.tm_year, t.tm_mon, t.tm_mday, 0, 0, 0, 0, 0, -1))
    monday = midnight - t.tm_wday * 86400
    # mktime again so a clock change inside the span lands on a real midnight
    m = time.localtime(monday - weeks_back * 7 * 86400 + 3 * 3600)
    return time.mktime((m.tm_year, m.tm_mon, m.tm_mday, 0, 0, 0, 0, 0, -1))


def _gb(b):
    return round(b / 1e9, 1)


def build(conn, start):
    """The digest of the week starting at `start` (a local Monday midnight)."""
    end = week_start(start + 8 * 86400)          # the next Monday, whatever the clock did
    out_kinds = reports.OUTAGE_KINDS
    totals = reports._stored_totals(conn, out_kinds, start, end)
    outages = sum(n for n, _ in totals.values())
    out_s = sum(s for _, s in totals.values())
    out_min = round(out_s / 60, 1)
    # whose side, as the outage log says it (reports.SIDE): the ISP's, the home's, or unclear
    sides = {side: sum(n for k, (n, _) in totals.items() if reports.SIDE.get(k) == side) for side in ("isp", "home", "unclear")}
    measured = reports.measured_s(conn, start, end)
    uptime = None if not measured else round(max(0.0, min(100.0, 100 * (1 - out_s / measured))), 3)
    slow = reports._stored(conn, ("problem", "slow"), start, end)
    # the slowest day: the most minutes in slow spells and problems, each split at midnight
    by_day = {}
    for e in slow:
        a, b = max(e["start"], start), min(e["end"], end)
        while a < b:
            t = time.localtime(a)
            midnight = time.mktime((t.tm_year, t.tm_mon, t.tm_mday + 1, 0, 0, 0, 0, 0, -1))
            piece = min(b, midnight) - a
            d = time.strftime("%A", t)
            by_day[d] = by_day.get(d, 0) + piece / 60
            a += piece
    slowest = max(by_day.items(), key=lambda kv: kv[1]) if by_day else None
    inet = reports._inet()
    marks = ",".join("?" * len(inet)) or "NULL"
    avgs = [a for (a,) in conn.execute(f"SELECT avg FROM pings_1m WHERE ts >= ? AND ts < ? AND target IN ({marks}) "
                                       "AND avg IS NOT NULL", (start, end, *inet))] if inet else []
    down, up, source = reports._period_totals(conn, start, end)
    top = None
    if source == "router":
        row = conn.execute("SELECT mac, SUM(rx) + SUM(tx) FROM usage_1h WHERE ts >= ? AND ts < ? GROUP BY mac "
                           "ORDER BY 2 DESC LIMIT 1", (start, end)).fetchone()
        if row:
            top = {"name": analysis._usage_namer(conn)(row[0]), "gb": _gb(row[1])}
    new_devices = [t for (t,) in conn.execute("SELECT text FROM alerts WHERE key LIKE 'newdev|%' AND first >= ? AND first < ?",
                                              (start, end))]
    (alerts_n,) = conn.execute("SELECT COUNT(*) FROM alerts WHERE key NOT LIKE 'newdev|%' AND first >= ? AND first < ?",
                               (start, end)).fetchone()
    tests = [dict(zip(("down", "up", "grade"), r)) for r in conn.execute(
        "SELECT down, up, grade FROM speedtests WHERE ts >= ? AND ts < ? AND error IS NULL ORDER BY ts", (start, end))]
    d = {"week_start": start, "week_end": end, "measured_s": measured, "uptime_pct": uptime,
         "outages": outages, "outage_minutes": out_min, "outage_sides": sides,
         "slow_spells": len(slow), "slowest_day": slowest and {"day": slowest[0], "minutes": round(slowest[1], 1)},
         "latency_ms": round(statistics.median(avgs), 1) if avgs else None,
         "usage": {"down_gb": _gb(down), "up_gb": _gb(up), "source": source, "top": top},
         "new_devices": new_devices, "alerts": alerts_n,
         "speedtests": {"count": len(tests), "last": tests[-1] if tests else None}}
    d["headline"] = headline(d)
    return d


def headline(d):
    """One plain sentence for the week."""
    if not d["measured_s"]:
        return "Hearth wasn't measuring last week."
    used = d["usage"]["down_gb"] + d["usage"]["up_gb"] if d["usage"]["source"] else None
    use = f", {used:.0f} GB used" if used is not None else ""
    if not d["outages"]:
        if d["slow_spells"] < QUIET_SLOW_SPELLS:
            return f"A quiet week: no outages{use}."
        return f"No outages, but a slow week ({d['slow_spells']} slow spells){use}."
    sides, n = d["outage_sides"], d["outages"]
    who = ("your ISP" if sides["isp"] == n else "your home network" if sides["home"] == n
           else "unclear where" if sides["unclear"] == n else "mixed causes")
    mins = "under a minute" if d["outage_minutes"] < 1 else f"{d['outage_minutes']:.0f} min"
    return f"{n} outage{'s' if n > 1 else ''} ({mins}, {who}){use}."


def store_week(conn, start):
    d = build(conn, start)
    conn.execute("INSERT OR REPLACE INTO digests (week_start, data) VALUES (?, ?)", (int(start), json.dumps(d)))
    conn.execute("DELETE FROM digests WHERE week_start < ?", (int(start - KEEP_WEEKS * 7 * 86400),))
    return d


def due(conn, now):
    """The week to build now, or None: last week, once it's Monday BUILD_HOUR or later and it
    isn't stored yet (at start, a missing last week is built straight away)."""
    last = week_start(now, 1)
    if now < week_start(now) + BUILD_HOUR * 3600 and conn.execute("SELECT 1 FROM digests LIMIT 1").fetchone():
        return None
    if conn.execute("SELECT 1 FROM digests WHERE week_start = ?", (int(last),)).fetchone():
        return None
    return last


def latest(conn):
    """The newest stored digest, or None."""
    row = conn.execute("SELECT data FROM digests ORDER BY week_start DESC LIMIT 1").fetchone()
    return json.loads(row[0]) if row else None
