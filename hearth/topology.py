"""Work out the shape of the home network from ping timing alone.

WiFi bridges, mesh nodes and switches don't route traffic, so traceroute can't see them.
They show up in two ways instead:

1. Latency relative to the router. A device reached *through* the same wireless hop
   as the router answers faster than the router; a device hanging off the router
   (or off another mesh node beyond it) answers slower.
2. Shared spikes. A wireless link that hiccups delays everything behind it at the same
   moment. If most of a device's spikes coincide with the router's, the device sits on
   the same troubled path; if its spikes are its own, it is local (or just busy).

Moments when almost every device spikes together are discarded: that is the machine
doing the measuring (a restart, a sweep, CPU load), not the network.

Everything here is a pure function of the samples, so it can be tested offline.
"""
import statistics

ROLE_LOCAL = "local"        # same segment as this machine
ROLE_RELAY = "relay"        # between this machine and the router (on the path)
ROLE_BRANCH = "branch"      # beyond / beside the router, not on the path
ROLE_UNSTABLE = "unstable"  # too lossy or jittery to judge (sleepy phones etc.)

MIN_SAMPLES = 60            # ~5 minutes at 5 s per device
MIN_SPIKES = 5              # spikes needed before the shared-spike evidence counts
SHARED_THRESHOLD = 0.5      # fraction of a device's spikes also seen at the router
GLOBAL_FRACTION = 0.75      # this share of devices spiking at once = measuring host, not network

# where each role can sit relative to the router's latency
_COMPATIBLE = {"local": ("before", "near"), "relay": ("before",), "branch": ("near",)}


def profile(samples, over_ms, bucket_s):
    """samples: [(ts, rtt|None)] -> stats and spike buckets for one target."""
    ok = sorted(r for _, r in samples if r is not None)
    if not ok:
        return None
    base = statistics.median(ok)
    limit = max(3 * base, base + over_ms)
    return {
        "n": len(samples),
        "loss": 1 - len(ok) / len(samples),
        "base": base,
        # the fast end reflects the path; the median also carries the device's own load
        # (a busy gaming PC answers slower), which blurs groups together
        "floor": ok[int(len(ok) * 0.1)],
        "p90": ok[min(len(ok) - 1, int(len(ok) * 0.9))],
        "spikes": {int(ts // bucket_s) for ts, r in samples if r is None or r > limit},
    }


def bands(items, key):
    """Split items sorted by latency wherever there's a clear jump (25% and 1.5 ms)."""
    items = sorted(items, key=key)
    out = []
    for it in items:
        if out and not (key(it) > key(out[-1][-1]) * 1.25 and key(it) - key(out[-1][-1]) > 1.5):
            out[-1].append(it)
        else:
            out.append([it])
    return out


def infer(series, devices, gateway, over_ms=25, bucket_s=5, excluded_buckets=frozenset(), previous=None):
    """
    series:   {target_id: [(ts, rtt|None), ...]} for the analysis window
    devices:  LAN device target ids to place (not the router / internet targets)
    gateway:  target id of the router
    previous: {device_id: {"role":..., "confident":bool}} from the last run, used when the
              current window is too calm to provide spike evidence
    returns   None if the router has too little data, else
              {"gateway_floor": ms, "roles": {id: {...}}, "local": [ids], "relays": [[ids]...],
               "branches": [[ids]...], "unstable": [ids]}
    """
    previous = previous or {}
    gs = series.get(gateway) or []
    gp = profile(gs, over_ms, bucket_s) if len(gs) >= MIN_SAMPLES else None
    if not gp:
        return None
    G = gp["floor"]
    margin = max(1.0, 0.1 * G)

    prof, unstable = {}, []
    for d in devices:
        s = series.get(d) or []
        p = profile(s, over_ms, bucket_s) if len(s) >= MIN_SAMPLES else None
        if not p:
            continue
        # sleepy WiFi clients (phones in power-save) answer erratically: not usable as evidence
        if p["loss"] > 0.2 or p["p90"] > max(3 * p["base"], p["base"] + 25):
            unstable.append(d)
            continue
        prof[d] = p

    # moments when nearly everything spiked at once are the measuring machine, not the network
    counts = {}
    for p in prof.values():
        for b in p["spikes"]:
            counts[b] = counts.get(b, 0) + 1
    need = max(3, GLOBAL_FRACTION * len(prof))
    noise = {b for b, c in counts.items() if c >= need} | set(excluded_buckets)
    gw_spikes = gp["spikes"] - noise
    gw_window = gw_spikes | {b + 1 for b in gw_spikes} | {b - 1 for b in gw_spikes}  # tolerate 5 s skew

    roles = {}
    for d, p in prof.items():
        spikes = p["spikes"] - noise
        shared = len(spikes & gw_window) / len(spikes) if len(spikes) >= MIN_SPIKES else None
        if p["floor"] < G - margin:
            side = "before"
        elif p["floor"] > G + margin:
            side = "after"
        else:
            side = "near"

        role, confident = None, shared is not None
        if side == "after":
            role, confident = ROLE_BRANCH, True
        elif side == "before" and shared is not None:
            role = ROLE_RELAY if shared >= SHARED_THRESHOLD else ROLE_LOCAL
        elif side == "near" and shared is not None:
            role = ROLE_BRANCH if shared >= SHARED_THRESHOLD else ROLE_LOCAL
        else:
            prev = previous.get(d)
            if prev and prev.get("confident") and side in _COMPATIBLE.get(prev.get("role"), ()):
                # calm window: keep the last evidence-backed answer, unless the latency now
                # makes it impossible (e.g. a branch device suddenly answering before the router
                # means the route changed)
                role, confident = prev["role"], True
            elif side == "near":
                # no evidence: whichever reference it sits closer to - the fastest *other* device
                # or the router. With no other device to compare against, local is the safer
                # guess (it keeps the device off the router's link in blame).
                others = [q["floor"] for o, q in prof.items() if o != d]
                ref = min(others) if others else None
                role = ROLE_LOCAL if ref is None or p["floor"] - ref < G - p["floor"] else ROLE_BRANCH
            # "before" without evidence is settled below by latency bands
        roles[d] = {"role": role, "confident": confident, "side": side, "base": round(p["base"], 2),
                    "floor": round(p["floor"], 2),
                    "shared": None if shared is None else round(shared, 2), "spikes": len(spikes)}

    # Settle "before" devices by latency band. The fastest band is always this computer's own
    # segment: nothing can sit between us and our fastest devices. Shared spikes there mean the
    # local segment (or this computer) hiccuped and took the router's replies with it - not that
    # those devices are a relay. Higher bands with no evidence are relays.
    # Overriding band 0 is deliberate: neither spike evidence nor a remembered role can put a
    # relay in front of the fastest devices. Unstable devices are never in `roles` at this
    # point (they are added below), so they can't join the bands.
    before = [d for d, r in roles.items() if r["side"] == "before"]
    for i, band in enumerate(bands(before, key=lambda d: prof[d]["floor"])):
        for d in band:
            if i == 0:
                roles[d]["role"] = ROLE_LOCAL
            elif roles[d]["role"] is None:
                roles[d]["role"] = ROLE_RELAY

    local = [d for d, r in roles.items() if r["role"] == ROLE_LOCAL]
    relays = bands([d for d, r in roles.items() if r["role"] == ROLE_RELAY], key=lambda d: prof[d]["floor"])
    branches = bands([d for d, r in roles.items() if r["role"] == ROLE_BRANCH], key=lambda d: prof[d]["floor"])
    for d in unstable:
        roles[d] = {"role": ROLE_UNSTABLE, "confident": False, "side": None, "base": None,
                    "shared": None, "spikes": 0}
    return {"gateway_floor": round(G, 2), "roles": roles, "local": local, "relays": relays,
            "branches": branches, "unstable": unstable, "noise_buckets": len(noise)}


def match_groups(new_groups, old_groups, next_id):
    """Give inferred groups stable ids across runs (and therefore stable user names).
    new_groups: [[member ids]]; old_groups: {id: set(members)}.
    Returns ([(id, members)], next_id)."""
    out, used = [], set()
    for members in new_groups:
        ms, best = set(members), None
        for gid, old in old_groups.items():
            if gid in used:
                continue
            j = len(ms & old) / len(ms | old)
            if j >= 0.3 and (best is None or j > best[0]):
                best = (j, gid)
        if best:
            used.add(best[1])
            out.append((best[1], members))
        else:
            out.append((next_id, members))
            next_id += 1
    return out, next_id
