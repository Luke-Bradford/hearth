"""Step 4, part 3a (#88): what the DNS check found - per resolver, over a range (the System tab),
and what needs attention now (the Overview). Reads dns_1m (collectors.dns_loop writes it)."""
import time

from . import analysis, levels as lv

ATTENTION_S = 180        # "now" for attention: the last three checks
SLOW_NOW_S = 600         # ...and ten minutes for "slow"
POINTS = 360             # a range's series is at most this many points
NO_ANSWER = "no resolver answered"   # the source's error then; "Needs attention" words it itself


def _name(resolver, gateway):
    return "Your router" if gateway and resolver == gateway else resolver


def dns_view(conn, minutes):
    """/api/dns: for each resolver asked in the range - its typical answer time, how often it
    didn't answer, its level, its latest answer, and a series of answer times."""
    now = time.time()
    since = now - minutes * 60
    gateway = analysis._gateway_ip(conn)
    bucket = max(60, int(minutes * 60 // POINTS) // 60 * 60)
    out = []
    for (resolver,) in conn.execute("SELECT DISTINCT resolver FROM dns_1m WHERE ts >= ? ORDER BY resolver", (since,)):
        rows = conn.execute("SELECT ts, ms, rcode FROM dns_1m WHERE resolver = ? AND ts >= ? ORDER BY ts",
                            (resolver, since)).fetchall()
        answered = [ms for _, ms, rcode in rows if rcode == 0 and ms is not None]
        stats = {"asked": len(rows), "fail_pct": round(100 * (1 - len(answered) / len(rows)), 1) if rows else 0,
                 "p50_ms": analysis.pct(answered, 0.5), "p95_ms": analysis.pct(answered, 0.95)}
        series = {}
        for ts, ms, rcode in rows:
            if rcode == 0 and ms is not None:
                series.setdefault(int(ts // bucket * bucket), []).append(ms)
        last = rows[-1] if rows else None
        out.append({"resolver": resolver, "name": _name(resolver, gateway), "router": resolver == gateway, **stats,
                    **lv.dns_level(stats),
                    "last": last and {"ts": last[0], "ms": last[1], "rcode": last[2]},
                    "series": [[t, round(sum(v) / len(v), 1)] for t, v in sorted(series.items())]})
    out.sort(key=lambda r: (not r["router"], r["resolver"]))
    return {"now": now, "bucket_s": bucket, "resolvers": out}


def attention(conn, now):
    """[(level, text)] for the Overview's "Needs attention": nothing answered in the last three
    checks; or the router didn't while another resolver did (so it's the router's DNS); or the
    router's answers have been slow for ten minutes."""
    gateway = analysis._gateway_ip(conn)
    recent = {}
    for resolver, ms, rcode in conn.execute("SELECT resolver, ms, rcode FROM dns_1m WHERE ts >= ?", (now - ATTENTION_S,)):
        recent.setdefault(resolver, []).append(rcode == 0 and ms is not None)
    if not recent:
        return []
    answering = {r for r, oks in recent.items() if any(oks)}
    if not answering:
        return [(lv.BAD, "DNS isn't answering: websites and apps can't find anything")]
    if gateway in recent and gateway not in answering:
        others = ", ".join(sorted(answering))
        return [(lv.BAD, f"Your router isn't answering DNS questions ({others} is): devices that use it may not open sites")]
    if gateway in recent:
        slow = [ms for (ms,) in conn.execute("SELECT ms FROM dns_1m WHERE resolver = ? AND ts >= ? AND rcode = 0",
                                             (gateway, now - SLOW_NOW_S)) if ms is not None]
        p50 = analysis.pct(slow, 0.5)
        if p50 is not None and p50 > lv.DNS_SLOW_FAIR:
            return [(lv.BAD if p50 > lv.DNS_SLOW_POOR else lv.WARN,
                     f"Your router's DNS is slow ({p50:.0f} ms an answer): every new site waits that long first")]
    return []
