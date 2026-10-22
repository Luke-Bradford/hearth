"""Step 4, part 1 (#88): the outage log and the ISP report card. Both read what Hearth already
keeps - stored episodes (400 days) and per-minute pings (400 days) - and add the episodes still
being built live; nothing new is collected.

Uptime is measured time minus outage time: minutes with no pings to the internet (Hearth wasn't
running) are left out, never counted as up."""
import json
import re
import statistics
import time

from . import analysis, episodes as ep, levels as lv, settings
from .config import CFG, inet_target

OUTAGE_DAYS = (7, 30, 90, 365)
OUTAGE_MAX = 2000        # rows returned; the totals always cover the whole window
OUTAGE_KINDS = (ep.KIND_HOME_DOWN, ep.KIND_OUTAGE, ep.KIND_INTERNET_DOWN)
# whose side an outage was on: the router answered but the internet didn't -> your ISP or beyond;
# the router didn't answer either -> your home network; the router wasn't measured -> unclear
SIDE = {ep.KIND_OUTAGE: "isp", ep.KIND_HOME_DOWN: "home", ep.KIND_INTERNET_DOWN: "unclear"}
REPORT_MONTHS_BACK = 13
MONTH_RE = re.compile(r"(\d{4})-(\d{2})")   # used with fullmatch
COVERAGE_PARTIAL = 0.5   # below this share of the month measured, the card says it's partial


def _inet():
    return [inet_target(ip) for ip in CFG["internet_targets"]]


def measured_s(conn, since, until):
    """Seconds in [since, until) with at least one per-minute ping row for an internet target."""
    inet = _inet()
    if not inet:
        return 0
    marks = ",".join("?" * len(inet))
    (n,) = conn.execute(f"SELECT COUNT(DISTINCT ts) FROM pings_1m WHERE ts >= ? AND ts < ? AND target IN ({marks})",
                        (since, until, *inet)).fetchone()
    return n * 60


def _overlap_s(e, since, until):
    return max(0, min(e["end"], until) - max(e["start"], since))


def _stored(conn, kinds, since, until, limit=None):
    marks = ",".join("?" * len(kinds))
    sql = (f"SELECT start, end, kind, data FROM episodes WHERE kind IN ({marks}) AND end >= ? AND start < ? "
           "ORDER BY start DESC" + (" LIMIT ?" if limit else ""))
    args = (*kinds, since, until) + ((limit,) if limit else ())
    out = []
    for s, e, k, d in conn.execute(sql, args):
        data = json.loads(d)
        out.append({"start": s, "end": e, "kind": k, "cause": data.get("cause"), "fault": data.get("fault"),
                    "lost_s": data.get("lost_s"), "truncated": bool(data.get("truncated"))})
    return out


def _stored_totals(conn, kinds, since, until):
    """{kind: (count, seconds inside the window)} over every stored episode of those kinds."""
    marks = ",".join("?" * len(kinds))
    return {k: (n, secs or 0) for k, n, secs in conn.execute(
        f"SELECT kind, COUNT(*), SUM(MIN(end, ?) - MAX(start, ?)) FROM episodes "
        f"WHERE kind IN ({marks}) AND end >= ? AND start < ? GROUP BY kind", (until, since, *kinds, since, until))}


def _live(conn, kinds, since, until, stored):
    """Episodes of those kinds still being built (not stored yet), that no stored one overlaps."""
    live = analysis.cached(analysis.incidents, conn, analysis.LIVE_S // 60)["episodes"]
    return [{"start": e["start"], "end": e["end"], "kind": e["kind"], "cause": e.get("cause"), "fault": e.get("fault"),
             "lost_s": e.get("lost_s"), "truncated": bool(e.get("truncated"))}
            for e in live if e.get("kind") in kinds and e["end"] >= since and e["start"] < until
            and not any(analysis._overlaps(e, s) for s in stored)]


def outages(conn, days, now=None):
    """The outage log for the last `days` (one of OUTAGE_DAYS): the outages newest first (at most
    OUTAGE_MAX, `limited` says when there were more), and totals over all of them."""
    now = now or time.time()
    since, until = now - days * 86400, now
    stored_recent = _stored(conn, OUTAGE_KINDS, since, until, OUTAGE_MAX + 1)
    near = [s for s in stored_recent if s["end"] >= now - analysis.LIVE_S - ep.EPISODE_GAP_S]
    live = _live(conn, OUTAGE_KINDS, since, until, near)
    rows = sorted(live + stored_recent, key=lambda e: e["start"], reverse=True)
    totals = {k: {"count": 0, "minutes": 0.0} for k in OUTAGE_KINDS}
    for k, (n, secs) in _stored_totals(conn, OUTAGE_KINDS, since, until).items():
        totals[k] = {"count": n, "minutes": round(secs / 60, 1)}
    for e in live:
        t = totals[e["kind"]]
        t["count"] += 1
        t["minutes"] = round(t["minutes"] + _overlap_s(e, since, until) / 60, 1)
    down_s = sum(t["minutes"] for t in totals.values()) * 60
    measured = measured_s(conn, since, until)
    up = None if not measured else max(0.0, min(100.0, 100 * (1 - down_s / measured)))
    return {"days": days, "since": since, "until": until,
            "outages": [{**e, "side": SIDE[e["kind"]]} for e in rows[:OUTAGE_MAX]],
            "limited": len(rows) > OUTAGE_MAX,
            "totals": totals, "measured_s": measured,
            "uptime_pct": None if up is None else round(up, 3), "uptime": lv.uptime_level(up),
            "kind_names": {k: ep.KIND_NAMES[k][0] for k in OUTAGE_KINDS}}


def month_bounds(month, now=None):
    """(start, end) of a calendar month in local time, for "YYYY-MM" within the last
    REPORT_MONTHS_BACK months (this month included), else None."""
    now = now or time.time()
    m = MONTH_RE.fullmatch(month or "")   # fullmatch: "$" would also accept a trailing newline
    if not m:
        return None
    y, mo = int(m.group(1)), int(m.group(2))
    if not 1 <= mo <= 12:
        return None
    cur = time.localtime(now)
    back = (cur.tm_year - y) * 12 + (cur.tm_mon - mo)
    if not 0 <= back <= REPORT_MONTHS_BACK:
        return None
    start = time.mktime((y, mo, 1, 0, 0, 0, 0, 0, -1))
    end = time.mktime((y + mo // 12, mo % 12 + 1, 1, 0, 0, 0, 0, 0, -1))
    return start, end


def this_month(now=None):
    return time.strftime("%Y-%m", time.localtime(now or time.time()))


def report(conn, month, now=None):
    """The ISP report card for a calendar month (see month_bounds), or None for a month out of
    range. Outages split by side; slow spells, with how many were on the line; latency and loss
    to the internet from the per-minute pings; the hour of the week that was worst; and how much
    of the month Hearth measured."""
    now = now or time.time()
    bounds = month_bounds(month, now)
    if not bounds:
        return None
    since, until = bounds[0], min(bounds[1], now)
    kinds = OUTAGE_KINDS + (ep.KIND_PROBLEM, ep.KIND_SLOW)
    stored = _stored(conn, kinds, since, until)
    near = [s for s in stored if s["end"] >= now - analysis.LIVE_S - ep.EPISODE_GAP_S]
    eps = stored + (_live(conn, kinds, since, until, near) if until > now - analysis.LIVE_S else [])
    sides = {side: {"count": 0, "minutes": 0.0} for side in ("isp", "home", "unclear")}
    slow = {"count": 0, "minutes": 0.0, "on_line": 0}
    for e in eps:
        mins = _overlap_s(e, since, until) / 60
        if e["kind"] in OUTAGE_KINDS:
            s = sides[SIDE[e["kind"]]]
            s["count"] += 1
            s["minutes"] = round(s["minutes"] + mins, 1)
        else:
            slow["count"] += 1
            slow["minutes"] = round(slow["minutes"] + mins, 1)
            slow["on_line"] += e.get("fault") in analysis.LINE_FAULTS
    measured = measured_s(conn, since, until)
    down_s = sum(s["minutes"] for s in sides.values()) * 60
    up = None if not measured else max(0.0, min(100.0, 100 * (1 - down_s / measured)))
    inet = _inet()
    marks = ",".join("?" * len(inet)) or "NULL"
    rows = conn.execute(f"SELECT ts, n, lost, avg FROM pings_1m WHERE ts >= ? AND ts < ? AND target IN ({marks})",
                        (since, until, *inet)).fetchall() if inet else []
    sent, lost = sum(r[1] for r in rows), sum(r[2] for r in rows)
    avgs = sorted(r[3] for r in rows if r[3] is not None)
    by_hour = {}
    for ts, _n, _lost, avg in rows:
        if avg is not None:
            t = time.localtime(ts)
            by_hour.setdefault((t.tm_wday, t.tm_hour), []).append(avg)
    worst = max(((k, statistics.median(v)) for k, v in by_hour.items() if len(v) >= 30),
                key=lambda kv: kv[1], default=None)
    latency = {"samples": sent, "loss_pct": round(100 * lost / sent, 2) if sent else 0,
               "p50": analysis.pct(avgs, 0.5), "p95": analysis.pct(avgs, 0.95)}
    return {"month": month, "this_month": this_month(now), "since": since, "until": until, "complete": until >= bounds[1],
            "measured_s": measured, "coverage": round(measured / max(1, until - since), 3),
            "partial": measured / max(1, until - since) < COVERAGE_PARTIAL,
            "uptime_pct": None if up is None else round(up, 3), "uptime": lv.uptime_level(up),
            "outages": sides, "slow": slow,
            "latency": {"p50_ms": latency["p50"], "p95_ms": latency["p95"], "loss_pct": latency["loss_pct"],
                        **lv.link_level(latency)},
            "worst_hour": None if not worst else {"weekday": worst[0][0], "hour": worst[0][1],
                                                  "median_ms": round(worst[1], 1)}}


# the cached(fn, conn, minutes) shape: the second argument is only the cache key
OUTAGES_TTL_S = REPORT_TTL_S = 60


def outages_view(conn, days):
    return outages(conn, days)


def months_back(month, now=None):
    """How many months before this one `month` is, or None when out of range (see month_bounds)."""
    now = now or time.time()
    if not month_bounds(month, now):
        return None
    cur = time.localtime(now)
    y, mo = map(int, month.split("-"))
    return (cur.tm_year - y) * 12 + (cur.tm_mon - mo)


def report_view(conn, back):
    cur = time.localtime()
    y, mo = divmod(cur.tm_year * 12 + cur.tm_mon - 1 - back, 12)
    return report(conn, f"{y:04d}-{mo + 1:02d}")


# ---------------------------------------------------------------- monthly usage (step 4.2)
USAGE_TOP = 20


def month_start_day():
    """The day a usage month begins (usage_month_starts, 1-28; anything else is 1)."""
    d = settings.value("usage_month_starts")
    return d if isinstance(d, int) and not isinstance(d, bool) and 1 <= d <= 28 else 1


def usage_bounds(month, now=None, day=None):
    """(start, end) of the usage month named "YYYY-MM": from `day` of that month to `day` of the
    next, local time; None when malformed or not begun yet. With day 15, "2026-10" runs 15
    October to 15 November. How far back is allowed is counted in usage months, by
    usage_months_back - not here in calendar months, which differ when the start day is ahead
    of today (#91)."""
    now = now or time.time()
    day = day or month_start_day()
    m = MONTH_RE.fullmatch(month or "")
    if not m or not 1 <= int(m.group(2)) <= 12:
        return None
    y, mo = int(m.group(1)), int(m.group(2))
    if (y, mo) > time.localtime(now)[:2]:   # not begun: checked before mktime, so "9999-12" is None, not an overflow
        return None
    start = time.mktime((y, mo, day, 0, 0, 0, 0, 0, -1))
    if start > now:
        return None
    end = time.mktime((y + mo // 12, mo % 12 + 1, day, 0, 0, 0, 0, 0, -1))
    return start, end


def current_usage_month(now=None, day=None):
    """The "YYYY-MM" of the usage month running now: before the start day, it's last month's."""
    t = time.localtime(now or time.time())
    day = day or month_start_day()
    y, m0 = divmod(t.tm_year * 12 + t.tm_mon - 1 - (t.tm_mday < day), 12)
    return f"{y:04d}-{m0 + 1:02d}"


def _period_totals(conn, since, until):
    """(down, up, source) over [since, until): the router's per-device hourly totals, else the
    router's own WAN counters (UPnP), else nothing."""
    rx, tx, n = conn.execute("SELECT COALESCE(SUM(rx),0), COALESCE(SUM(tx),0), COUNT(*) FROM usage_1h "
                             "WHERE ts >= ? AND ts < ?", (since, until)).fetchone()
    if n:
        return rx, tx, "router"
    rx, tx, n = conn.execute("SELECT COALESCE(SUM(rx),0), COALESCE(SUM(tx),0), COUNT(*) FROM traffic_wan_1h "
                             "WHERE ts >= ? AND ts < ?", (since, until)).fetchone()
    return (rx, tx, "wan") if n else (0, 0, None)


def monthly_usage(conn, month, now=None):
    """Usage for one usage month (see usage_bounds): the total, each day, the top devices (from
    the router's per-device counts; the WAN counters give only totals), and the month before's
    total for comparison. None when the month is out of range."""
    now = now or time.time()
    day = month_start_day()
    bounds = usage_bounds(month, now, day)
    if not bounds:
        return None
    since, end = bounds
    until = min(end, now)
    down, up, source = _period_totals(conn, since, until)
    table = "usage_1h" if source == "router" else "traffic_wan_1h"
    days = {}
    if source:
        for ts, rx, tx in conn.execute(f"SELECT ts, SUM(rx), SUM(tx) FROM {table} WHERE ts >= ? AND ts < ? GROUP BY ts",
                                       (since, until)):
            d = days.setdefault(time.strftime("%Y-%m-%d", time.localtime(ts)), [0, 0])
            d[0] += rx or 0
            d[1] += tx or 0
    devices = []
    if source == "router":
        name = analysis._usage_namer(conn)
        rows = conn.execute("SELECT mac, SUM(rx), SUM(tx) FROM usage_1h WHERE ts >= ? AND ts < ? GROUP BY mac "
                            "ORDER BY SUM(rx) + SUM(tx) DESC", (since, until)).fetchall()
        devices = [{"mac": mac, "name": name(mac), "down": rx, "up": tx} for mac, rx, tx in rows[:USAGE_TOP]]
        rest = rows[USAGE_TOP:]
        if rest:
            devices.append({"mac": None, "name": "Everything else", "down": sum(r[1] for r in rest),
                            "up": sum(r[2] for r in rest)})
    y, mo = map(int, month.split("-"))
    py, pm = divmod(y * 12 + mo - 2, 12)
    prev = usage_bounds(f"{py:04d}-{pm + 1:02d}", now, day)
    pdown, pup, _ = _period_totals(conn, *prev) if prev else (0, 0, None)
    return {"month": month, "current": current_usage_month(now, day), "starts_day": day, "since": since, "until": until, "end": end,
            "complete": now >= end, "source": source, "down": down, "up": up,
            "days": [{"date": k, "down": v[0], "up": v[1]} for k, v in sorted(days.items())],
            "devices": devices, "previous": {"down": pdown, "up": pup} if prev else None}


def usage_month_view(conn, back):
    """The cached(fn, conn, key) shape: `back` usage months before the current one."""
    y, mo = map(int, current_usage_month().split("-"))
    y, m0 = divmod(y * 12 + mo - 1 - back, 12)
    return monthly_usage(conn, f"{y:04d}-{m0 + 1:02d}")


def usage_months_back(month, now=None):
    """How many usage months before the current one `month` is (0-13), or None."""
    now = now or time.time()
    if not MONTH_RE.fullmatch(month or "") or not usage_bounds(month, now):
        return None
    cy, cm = map(int, current_usage_month(now).split("-"))
    y, mo = map(int, month.split("-"))
    back = (cy - y) * 12 + (cm - mo)
    return back if 0 <= back <= REPORT_MONTHS_BACK else None
