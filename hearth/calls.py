"""Step 4, part 3b (#88): would a call sound right? Rated from the pings Hearth already sends to
the internet - round trip, jitter and loss per minute (pings_1m) - with levels.call_quality's
E-model. No new traffic.

A minute where every ping was lost is a minute a call would have failed: it counts, with 100%
lost, never dropped (#95) - so an outage reads as poor, not as the good minutes around it."""
import time

from . import levels as lv
from .config import CFG, inet_target

NOW_MIN = 5          # "now": the last five whole minutes
SERIES_MIN = 120     # the tile's sparkline: two hours, a point a minute


def _sums(conn, since, until):
    """{minute: [sent, lost, rtt x replies, jitter x replies-with-jitter, replies-with-jitter]}
    across the internet targets."""
    inet = [inet_target(ip) for ip in CFG["internet_targets"]]
    if not inet:
        return {}
    marks = ",".join("?" * len(inet))
    by = {}
    for ts, n, lost, avg, jitter in conn.execute(
            f"SELECT ts, n, lost, avg, jitter FROM pings_1m WHERE ts >= ? AND ts < ? AND target IN ({marks})",
            (since, until, *inet)):
        b = by.setdefault(ts, [0, 0, 0.0, 0.0, 0])
        replies = n - lost
        b[0] += n
        b[1] += lost
        if avg is not None and replies:
            b[2] += avg * replies
        if jitter is not None and replies:
            b[3] += jitter * replies
            b[4] += replies
    return by


def _stats(sent, lost, rtt_w, jit_w, jit_n):
    """{rtt_ms, jitter_ms, loss_pct} from summed counts: round trip and jitter weighted by
    replies, loss over everything sent. Nothing answered: no round trip, 100% lost."""
    replies = sent - lost
    return {"rtt_ms": rtt_w / replies if replies else None, "jitter_ms": jit_w / jit_n if jit_n else 0.0,
            "loss_pct": round(100 * lost / sent, 2)}


def calls_kpi(conn, now=None):
    """{level, why, mos, rtt_ms, jitter_ms, loss_pct, series:[[ts, mos]]} - the last NOW_MIN
    minutes rated together (their counts summed), and each of the last SERIES_MIN minutes alone."""
    now = now or time.time()
    end = int(now // 60 * 60)
    by = {ts: b for ts, b in _sums(conn, end - SERIES_MIN * 60, end).items() if b[0]}
    recent = [b for ts, b in by.items() if ts >= end - NOW_MIN * 60]
    stats = _stats(*[sum(b[i] for b in recent) for i in range(5)]) if recent else None
    q = lv.call_quality(stats)
    shown = {k: (round(v, 1) if v is not None else None) for k, v in stats.items()} if stats else {}
    return {**q, **shown, "series": [[ts, lv.call_quality(_stats(*b))["mos"]] for ts, b in sorted(by.items())]}


POINTS = 360        # a range's chart is at most this many points


def quality_view(conn, minutes):
    """/api/quality: for the History tab - the call rating over the range (minutes summed into
    buckets as the tile sums its five: an outage minute counts) and each resolver's DNS answer
    time (dns_health)."""
    from . import dns_health   # here: dns_health imports analysis, which imports this module
    now = time.time()
    end = int(now // 60 * 60)
    bucket = max(60, int(minutes * 60 // POINTS) // 60 * 60)
    buckets = {}
    for ts, b in _sums(conn, end - minutes * 60, end).items():
        acc = buckets.setdefault(int(ts // bucket * bucket), [0, 0, 0.0, 0.0, 0])
        for i in range(5):
            acc[i] += b[i]
    mos = [[ts, lv.call_quality(_stats(*b))["mos"]] for ts, b in sorted(buckets.items()) if b[0]]
    dns = [{"name": r["name"], "resolver": r["resolver"], "router": r["router"], "points": r["series"]}
           for r in dns_health.dns_view(conn, minutes)["resolvers"]]
    return {"now": now, "bucket_s": bucket, "mos": mos, "dns": dns}
