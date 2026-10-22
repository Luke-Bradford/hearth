"""Every status level in one place (#38, step 1, part 2): the thresholds that turn a
measurement into ok / warn / bad / unknown, and the sentence that explains it. The page only
displays what these return, so the header, tiles, map and tables can't disagree.
Pure functions: no Hearth imports, no database."""
OK, WARN, BAD, UNKNOWN = "ok", "warn", "bad", "unknown"
_RANK = {UNKNOWN: 0, OK: 1, WARN: 2, BAD: 3}

LOSS_POOR, LOSS_FAIR = 5.0, 1.0          # % of pings lost
SLOW_POOR, SLOW_FAIR = 100.0, 40.0       # ms the slowest 5% sit above the typical reply
RSSI_GOOD, RSSI_FAIR = -65, -75          # dBm: the usual Wi-Fi rules of thumb
CHANNEL_BUSY_WARN, CHANNEL_BUSY_BAD = 40, 60  # % of airtime a WiFi channel is busy
UPTIME_FAIR, UPTIME_POOR = 99.9, 99.0      # % of measured time the internet answered (99.9% = 43 min a month)
DNS_SLOW_FAIR, DNS_SLOW_POOR = 200.0, 1000.0  # ms a resolver takes to answer: a page waits this long first
DNS_FAIL_FAIR, DNS_FAIL_POOR = 2.0, 10.0     # % of questions with no answer
CALL_GOOD, CALL_FAIR = 4.0, 3.6             # MOS (1-5): a call that sounds good / still fine
CODEC_MS = 20.0                              # the delay a voice codec adds, one way
BLOAT_A, BLOAT_B, BLOAT_C = 30.0, 60.0, 200.0  # ms a full line adds to the round trip: grades A/B/C, D above


def result(level, why):
    """The shape every level function returns."""
    return {"level": level, "why": why}


def rank(level):
    """bad 3 > warn 2 > ok 1 > unknown 0 - for picking the worst."""
    return _RANK.get(level, 0)


def worst(levels):
    """The most severe level; unknown only if nothing is known."""
    levels = list(levels)
    return max(levels, key=rank) if levels else UNKNOWN


def worst_of(results):
    """The most severe {level, why} of several (the first of equals), or unknown."""
    results = [r for r in results if r]
    return max(results, key=lambda r: rank(r["level"])) if results else result(UNKNOWN, "not measured yet")


def _judge(loss, extra):
    if loss > LOSS_POOR or extra > SLOW_POOR:
        return BAD
    if loss > LOSS_FAIR or extra > SLOW_FAIR:
        return WARN
    return OK


def uptime_level(pct):
    """How much of the measured time the internet answered: 99.9% and up is good."""
    if pct is None:
        return result(UNKNOWN, "not measured")
    level = OK if pct >= UPTIME_FAIR else WARN if pct >= UPTIME_POOR else BAD
    return result(level, f"up {pct:.2f}% of the time Hearth was measuring")


def dns_level(stats):
    """A resolver, from how often it didn't answer and how long a typical answer took."""
    if not stats or not stats.get("asked"):
        return result(UNKNOWN, "not asked yet")
    fail, p50 = stats.get("fail_pct") or 0, stats.get("p50_ms")
    if fail >= 100 or p50 is None:
        return result(BAD, "not answering")
    level = BAD if fail > DNS_FAIL_POOR or p50 > DNS_SLOW_POOR else WARN if fail > DNS_FAIL_FAIR or p50 > DNS_SLOW_FAIR else OK
    return result(level, f"answers in {p50:.0f} ms typically, {fail:g}% unanswered")


def mos(rtt_ms, jitter_ms, loss_pct):
    """How a voice call would sound, 1 (bad) to 4.5 (best): a simplified E-model (ITU-T G.107)
    from the one-way delay (half the round trip, plus a codec's delay, plus twice the jitter a
    playout buffer would add) and the packets lost."""
    one_way = rtt_ms / 2 + CODEC_MS + 2 * jitter_ms
    r = 93.2 - (one_way / 40 if one_way < 160 else (one_way - 120) / 10) - 2.5 * loss_pct
    if r <= 0:
        return 1.0
    if r >= 100:
        return 4.5
    return round(min(4.5, 1 + 0.035 * r + 7e-6 * r * (r - 60) * (100 - r)), 2)


def call_quality(stats):
    """A call over the internet now, from round trip, jitter and loss to the internet."""
    if not stats:
        return {**result(UNKNOWN, "not measured yet"), "mos": None}
    if stats.get("rtt_ms") is None or (stats.get("loss_pct") or 0) >= 100:
        return {**result(BAD, "no replies from the internet: a call would fail"), "mos": 1.0}
    m = mos(stats["rtt_ms"], stats.get("jitter_ms") or 0, stats.get("loss_pct") or 0)
    level, word = (OK, "good") if m >= CALL_GOOD else (WARN, "fair") if m >= CALL_FAIR else (BAD, "poor")
    why = (f"{word} for calls: {stats['rtt_ms']:.0f} ms round trip, {stats.get('jitter_ms') or 0:.1f} ms jitter, "
           f"{stats.get('loss_pct') or 0:g}% lost")
    return {**result(level, why), "mos": m}


def bufferbloat(idle_ms, loaded_down_ms, loaded_up_ms):
    """How much lag a full line adds (the worse direction): grade A-D and a level. A is under
    BLOAT_A ms, B under BLOAT_B, C under BLOAT_C, D above."""
    rises = [x - idle_ms for x in (loaded_down_ms, loaded_up_ms) if x is not None and idle_ms is not None]
    if not rises:
        return {**result(UNKNOWN, "no pings during the test to compare"), "grade": None, "rise_ms": None}
    rise = max(0.0, max(rises))
    grade = "A" if rise < BLOAT_A else "B" if rise < BLOAT_B else "C" if rise < BLOAT_C else "D"
    level = OK if grade in "AB" else WARN if grade == "C" else BAD
    return {**result(level, f"a full line adds {rise:.0f} ms of lag"), "grade": grade, "rise_ms": round(rise, 1)}


def link_level(stats):
    """A device or one target, from its lost pings and how far its slowest 5% sit above its
    own typical reply. (Groups take the worst of their members: analysis.group_level.)"""
    if not stats or not stats.get("samples"):
        return result(UNKNOWN, "not measured yet")
    loss = stats.get("loss_pct") or 0
    if stats.get("p95") is None or loss >= 100:   # the same rule as device_level
        return result(BAD, f"no replies ({loss:g}% lost)")
    # p50 and p95 come from the same replies (target_stats), so one is never missing alone
    extra = stats["p95"] - stats["p50"] if stats.get("p50") is not None else 0
    why = f"{loss:g}% lost, slowest 5% {stats['p95']:.0f} ms ({extra:+.0f} ms over typical)"
    return result(_judge(loss, extra), why)


def device_level(stats, node_stats, sleepy=False):
    """A wireless device, judged against the mesh unit it hangs off (the mesh doesn't report
    per-device signal): its lost pings, and how far its slowest 5% sit above its unit's."""
    if not stats or not stats.get("samples"):
        return result(UNKNOWN, "not measured yet")
    loss = stats.get("loss_pct") or 0
    if stats.get("p95") is None or loss >= 100:
        return result(BAD, f"no answers in the last hour ({loss:g}% lost)")
    if sleepy:
        return {**result(UNKNOWN, "answers erratically - usually power saving (phones, tablets), not a bad connection"),
                "power_saving": True}
    base = (node_stats or {}).get("p95")
    if base is None:
        lv = BAD if loss > LOSS_POOR else WARN if loss > LOSS_FAIR else OK
        return result(lv, f"{loss:g}% lost (its mesh unit isn't measured, so latency isn't judged)")
    extra = stats["p95"] - base
    return result(_judge(loss, extra), f"{loss:g}% lost, slowest 5% {stats['p95']:.0f} ms ({extra:+.0f} ms vs its mesh unit)")


def signal_level(dbm):
    if dbm is None:
        return result(UNKNOWN, "no signal reading")
    lv = OK if dbm >= RSSI_GOOD else WARN if dbm >= RSSI_FAIR else BAD
    return result(lv, f"{dbm} dBm" + ("" if lv == OK else " - fair" if lv == WARN else " - weak"))


def internet_level(st):
    """The internet right now, from analysis.status(): lost pings over 5 minutes, and how far
    the slowest 5% sit above the typical ping - the same limits as everything else."""
    loss, p50, p95 = st.get("loss_pct_5m"), st.get("internet_ms"), st.get("internet_p95_ms")
    if loss is None:                       # no internet pings at all in the last 5 minutes
        return result(UNKNOWN, "not measured yet")
    # internet_measured comes from status(), which always sets it; a dict without it (an older
    # caller) is treated as measured, so only an explicit False means "no pings in 15 s"
    if st.get("internet_measured") is False:   # no pings in the last 15 s: Hearth restarting, a
        return result(UNKNOWN, "not measured in the last few seconds")  # stalled pinger - not an outage
    if not st.get("internet_up"):          # pings sent in the last 15 s, none answered
        return result(BAD, "no answers from the internet right now")
    if p95 is None or p50 is None:
        return result(UNKNOWN, "not enough replies to judge yet")
    return result(_judge(loss, p95 - p50), f"{loss:g}% lost, slowest 5% {p95:.0f} ms (typical {p50:.0f} ms)")


def temp_level(temp, warn, bad):
    if temp is None:
        return result(UNKNOWN, "no temperature reading")
    lv = BAD if temp >= bad else WARN if temp >= warn else OK
    return result(lv, f"{temp:g} °C" + ("" if lv == OK else f" (amber from {warn:g} °C, red from {bad:g} °C)"))


def channel_level(util):
    """A WiFi channel's airtime use: busy channels slow everyone on them down."""
    if util is None:
        return result(UNKNOWN, "no reading")
    lv = BAD if util >= CHANNEL_BUSY_BAD else WARN if util >= CHANNEL_BUSY_WARN else OK
    return result(lv, f"{util:g}% busy")
