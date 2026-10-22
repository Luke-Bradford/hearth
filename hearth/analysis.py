"""Turn raw pings plus the inferred layout into what the dashboard shows: the chain of links
from this computer to the internet, per-device stats, and incidents with the link to blame."""
import bisect
import itertools
import json
import math
import sqlite3
import statistics
import threading
import time
from collections import OrderedDict

from . import alerts, calls, digest, episodes as ep, host, levels as lv, live, mesh, net, placement, router, sources, speedtest, store
from .config import (CFG, DEFAULTS, EV_PATH, GROUP_PREFIX, INET_PREFIX, POS_GATEWAY, POS_INTERNET, POS_ISP, POS_LOCAL,
                     POS_RELAY, STATE_ASLEEP, TARGET_GATEWAY, TARGET_ISP, GATEWAY_STATE_KEY, GATEWAY_STALE_SWEEPS, device_target,
                     inet_target, log)
from .naming import (PLACEHOLDER_NAME, device_names, device_rows, fallback_name, group_label, group_name,
                     group_short, normalise_mac, router_names)

OVER = float(CFG["spike_over_baseline_ms"])
LINE_POSITIONS = (POS_ISP, POS_INTERNET)
# the links of the chain on the line side: a fault named by one of these is your ISP or beyond
LINK_ISP, LINK_BEYOND, LINK_LINE = "Broadband line (router to ISP)", "Internet beyond your ISP", "Broadband line / internet"
LINE_FAULTS = (LINK_ISP, LINK_BEYOND, LINK_LINE)


def pct(vals, p):
    if not vals:
        return None
    vals = sorted(vals)
    k = (len(vals) - 1) * p
    f = int(k)
    c = min(f + 1, len(vals) - 1)
    return round(vals[f] + (vals[c] - vals[f]) * (k - f), 2)


def is_spike(rtt, base, over=OVER):
    if rtt is None:
        return True
    if base is None:
        return False
    return rtt > max(base * 3, base + over)


def fetch_raw(conn, since, until=None):
    by = {}
    q = "SELECT ts, target, rtt FROM pings WHERE ts >= ?" + (" AND ts < ?" if until is not None else "") + " ORDER BY ts"
    for ts, name, rtt in conn.execute(q, (since,) if until is None else (since, until)):
        by.setdefault(name, []).append((ts, rtt))
    return by


def baselines(by):
    return {n: (statistics.median([r for _, r in s if r is not None]) if any(r is not None for _, r in s) else None)
            for n, s in by.items()}


def floors_of(snap):
    """{device id: fastest-10% latency} from a layout snapshot, used to name groups."""
    return {d: r.get("floor") for d, r in ((snap or {}).get("roles") or {}).items()}


MESH_MAX_AGE_S = 86400  # the mesh layout rarely changes: a day-old reading still names groups


_mesh_cache, _mesh_lock = {"ts": 0.0, "val": None}, threading.Lock()
MESH_INDEX_TTL_S = 30


def mesh_index(conn):
    """What the mesh system says, keyed for the timing analysis: {"nodes": {mac: node},
    "where": {target id: node mac}, "self": node mac} (a device is where the mesh says it's
    connected; a mesh node is "at" itself). None when the mesh isn't read. Cached briefly
    (status is polled often); a new mesh reading clears it via clear_cache()."""
    with _mesh_lock:
        if time.time() - _mesh_cache["ts"] < MESH_INDEX_TTL_S:
            return _mesh_cache["val"]
    val = _build_mesh_index(conn)
    with _mesh_lock:
        _mesh_cache.update(ts=time.time(), val=val)
    return val


def _build_mesh_index(conn):
    snap = store.get_state(conn, mesh.MESH_STATE_KEY)
    if not snap or time.time() - snap.get("ts", 0) > MESH_MAX_AGE_S:
        return None
    nodes = {n["mac"]: n for n in snap.get("nodes", [])}
    by_ip = {}
    for n in nodes.values():
        if n.get("ip"):
            by_ip[n["ip"]] = n["mac"]
    for c in snap.get("clients", []):
        if c.get("ip"):
            by_ip.setdefault(c["ip"], c["node"])
    where = {device_target(c["mac"], None): c["node"] for c in snap.get("clients", [])}
    where.update({device_target(m, None): m for m in nodes})
    # Hearth's own device ids: by MAC first. An address is only trusted for a mesh node (whose
    # own MAC may differ from the one Hearth sees) or a row with no MAC - a stale row whose old
    # address DHCP has since given to another device must not inherit that device's place
    by_mac = {c["mac"]: c["node"] for c in snap.get("clients", [])}
    by_mac.update({m: m for m in nodes})
    node_ips = {n["ip"]: n["mac"] for n in nodes.values() if n.get("ip")}
    for ip, mac in conn.execute("SELECT ip, mac FROM devices"):
        mac = normalise_mac(mac) if mac else None
        tid = device_target(mac, ip)
        if mac and mac in by_mac:
            where.setdefault(tid, by_mac[mac])
        elif ip in node_ips or (not mac and ip in by_ip):
            where.setdefault(tid, node_ips.get(ip) or by_ip[ip])
    my_ip = _my_ip()
    return {"nodes": nodes, "where": where, "self": by_ip.get(my_ip) if my_ip else None}


QUALITY_WINDOW_MIN = 60  # wireless devices are judged on the last hour of pings


_gw_cache, _gw_lock = {"ts": 0.0, "ip": None}, threading.Lock()


def _gateway_ip(conn, ttl=300):
    """The router's address: the config's "gateway" if set (an override), else as discovery
    last found it (saved each sweep; ignored once GATEWAY_STALE_SWEEPS sweeps old, so a router
    that moved isn't remembered at its old address), else the default route - cached, since
    that lookup runs a command on Windows. A failed lookup isn't cached, so it's retried next
    time rather than leaving the router unknown."""
    if CFG.get("gateway"):
        return CFG["gateway"]
    saved = store.get_state(conn, GATEWAY_STATE_KEY)
    if (isinstance(saved, dict) and isinstance(saved.get("ip"), str) and isinstance(saved.get("ts"), (int, float))
            and time.time() - saved["ts"] <= GATEWAY_STALE_SWEEPS * CFG["discovery_interval_s"]):
        return saved["ip"]
    with _gw_lock:
        if _gw_cache["ip"] is None or time.time() - _gw_cache["ts"] > ttl:
            _gw_cache.update(ts=time.time(), ip=net.default_gateway())
        return _gw_cache["ip"]


def device_floors(conn, now):
    """{device id: (floor ms, replies)}: the 5th percentile of each device's replies over the
    last placement.FLOOR_WINDOW_S - how fast it can answer at best, which says where it hangs.
    Same interpolation as pct(), but SQLite ranks the replies and returns only the two each
    percentile sits between, so the window's rows never come into Python (SQLite 3.25+, for
    window functions; older builds get the same answer the slower way)."""
    q = placement.FLOOR_PCT
    since = now - placement.FLOOR_WINDOW_S
    if sqlite3.sqlite_version_info < (3, 25, 0):
        rows = {}
        for t, r in conn.execute("SELECT target, rtt FROM pings WHERE ts >= ? AND rtt IS NOT NULL AND target LIKE 'dev:%'",
                                 (since,)):
            rows.setdefault(t, []).append(r)
        return {t: (pct(v, q), len(v)) for t, v in rows.items()}
    by = {}
    for t, n, k, r in conn.execute(
            "SELECT target, n, rn - 1, rtt FROM ("
            " SELECT target, rtt, row_number() OVER (PARTITION BY target ORDER BY rtt) AS rn,"
            " count(*) OVER (PARTITION BY target) AS n FROM pings"
            " WHERE ts >= ? AND rtt IS NOT NULL AND target LIKE 'dev:%')"
            " WHERE rn - 1 BETWEEN CAST((n - 1) * ? AS INTEGER) AND CAST((n - 1) * ? AS INTEGER) + 1",
            (since, q, q)):
        by.setdefault(t, [n, {}])[1][k] = r
    out = {}
    for t, (n, v) in by.items():
        k = (n - 1) * q
        f = int(k)
        c = min(f + 1, n - 1)
        out[t] = (round(v[f] + (v[c] - v[f]) * (k - f), 2), n)
    return out


def floors_view(conn, _minutes):  # _minutes: only the cache key
    return device_floors(conn, time.time())


def mesh_view(conn, minutes=60):
    """The mesh layout for the map, and how well it's connected: nodes (uplink, backhaul signal
    and link rates, findings, a signal history), and devices with the node they're on, how
    (cable / band), what kind of device the mesh thinks it is, and - for wireless devices - a
    connection-quality grade from Hearth's own pings."""
    now = time.time()
    snap = store.get_state(conn, mesh.MESH_STATE_KEY)
    err = store.get_state(conn, mesh.MESH_ERROR_KEY)
    pending = mesh.pending_cert(conn)  # a changed certificate for you to confirm (shown either way)
    if not snap or now - snap.get("ts", 0) > MESH_MAX_AGE_S:
        # same cut-off as the analysis: an old reading isn't drawn as the current layout
        return {"available": False, "error": err, "stale_since": snap.get("ts") if snap else None,
                "pending_cert": pending}
    devnames, labels, routed = device_names(conn), store.labels(conn), router_names(conn)

    # what's usual for each satellite's link: median rate per band over the last day. A link that
    # has been poor for most of the day drags its own "usual" down, so the "under half" finding
    # catches drops, not long degradation - the signal grade covers that case
    usual, usual_tx = {}, {}
    for mac, band, rx, tx in conn.execute("SELECT mac, band, rate_rx, rate_tx FROM mesh_backhaul WHERE ts >= ?",
                                          (now - 86400,)):
        if rx is not None:
            usual.setdefault(mac, {}).setdefault(band, []).append(rx)
        if tx is not None:
            usual_tx.setdefault(mac, {}).setdefault(band, []).append(tx)
    usual, usual_tx = ({m: {b: int(statistics.median(v)) for b, v in bands.items()} for m, bands in u.items()}
                       for u in (usual, usual_tx))

    nodes, findings = [], []
    for n in snap.get("nodes", []):
        node = {k: n.get(k) for k in ("mac", "ip", "name", "model", "role", "parent", "backhaul", "bands",
                                       "signal", "online", "rssi", "rate_rx", "rate_tx")}
        node["grades"] = {b: mesh.rssi_grade(v) for b, v in (n.get("rssi") or {}).items()}
        node["band_levels"] = {b: lv.signal_level(v)["level"] for b, v in (n.get("rssi") or {}).items()}
        node["usual_rx"] = usual.get(n["mac"], {})
        node["usual_tx"] = usual_tx.get(n["mac"], {})
        node["findings"] = [{"level": lvl, "text": t}
                            for lvl, t in mesh.backhaul_findings(n, usual.get(n["mac"]), usual_tx.get(n["mac"]))]
        findings += node["findings"]
        nodes.append(node)

    # signal history per satellite and band, for the chart
    since = now - minutes * 60
    hourly = long_range(minutes)   # beyond the detail rows' retention: the hourly summaries
    unit = 3600 if hourly else 300   # whole hours from the hourly table, 5-minute steps otherwise
    bucket = max(unit, int(minutes * 60 / 200) // unit * unit)
    table, col = ("mesh_backhaul_1h", "rssi_avg") if hourly else ("mesh_backhaul", "rssi")
    history = {}
    for mac, band, b, rssi in conn.execute(
            f"""SELECT mac, band, CAST(ts / ? AS INTEGER) * ?, AVG({col}) FROM {table}
               WHERE ts >= ? AND {col} IS NOT NULL GROUP BY mac, band, 3 ORDER BY 3""", (bucket, bucket, since)):
        history.setdefault(f"{mac}|{band}", []).append([b, round(rssi, 1)])

    # Hearth's ping stats for judging wireless devices (and the units they hang off)
    stats_by_id = {d["id"]: d for d in cached(summary, conn, QUALITY_WINDOW_MIN)["devices"]}
    # an address can belong to more than one of Hearth's records (an old row, a second
    # address on the same card): prefer the record that actually has ping stats
    id_by_ip = {}
    for r in device_rows(conn):
        if r[1] and (r[1] not in id_by_ip or (r[0] in stats_by_id and id_by_ip[r[1]] not in stats_by_id)):
            id_by_ip[r[1]] = r[0]

    def stats_for(tid, ip):
        return stats_by_id.get(tid) or stats_by_id.get(id_by_ip.get(ip))
    node_stats = {n["mac"]: stats_for(device_target(n["mac"], None), n.get("ip")) for n in nodes}
    for node in nodes:
        if not node.get("online"):
            res = lv.result(lv.BAD, "not connected to the mesh")
        elif node.get("role") == "main" or node.get("backhaul") == "wired":
            res = lv.link_level(node_stats.get(node["mac"]))
        else:
            rssi = node.get("rssi") or {}
            res = lv.signal_level(max(rssi.values()) if rssi else None)
        # (an online wireless unit with no signal reading is unknown, not a problem: the mesh
        # simply didn't report it; offline is handled above)
        # a finding (2.4 GHz only, rate drop, weak link) can only raise the level; its text
        # is the reason - the worst finding's, not just the first
        node.update(lv.worst_of([res] + [lv.result(f["level"], f["text"]) for f in node["findings"]]))

    devices = []
    for c in snap.get("clients", []):
        tid = device_target(c["mac"], None)
        d = {"id": tid, "mac": c["mac"], "ip": c.get("ip"), "node": c["node"], "link": c.get("link"),
             "kind": c.get("kind"), "network": c.get("network"),
             "name": labels.get(tid) or devnames.get(tid) or routed.get(c["mac"])
             or (c.get("name") if c.get("name") and not PLACEHOLDER_NAME.match(c["name"]) else None)
             or fallback_name(net.vendor(c["mac"]), c["mac"])}
        s = stats_for(tid, d["ip"])
        if d["link"] and d["link"].startswith("band"):
            sleepy = (s or {}).get("role") == "unstable"
            d["quality"], d["quality_why"] = mesh.device_quality(s, node_stats.get(c["node"]), sleepy=sleepy)  # kept
            r = lv.device_level(s, node_stats.get(c["node"]), sleepy=sleepy)
            d.update(level=r["level"], why=r["why"])  # not device_level's internal power_saving flag
        else:
            d.update(lv.link_level(s))
        devices.append(d)
    my_ip = _my_ip()
    for d in devices:
        d["placement"] = "mesh"
    unit_macs = {n["mac"].lower() for n in snap.get("nodes", [])}   # one MAC format on both sides
    listed = {c["mac"].lower() for c in snap.get("clients", [])}
    # a unit or a listed client can sit in Hearth's records under another MAC (a radio MAC, a
    # shared one): its address identifies it too, as elsewhere (mesh_node_ips, the page's pick())
    taken_ips = {n.get("ip") for n in snap.get("nodes", [])} | {c.get("ip") for c in snap.get("clients", [])}
    taken_ips.discard(None)
    gw = _gateway_ip(conn)
    floors = cached(floors_view, conn, placement.FLOOR_WINDOW_S // 60, ttl=placement.FLOOR_REFRESH_S)
    unit_names = {n["mac"]: n.get("name") or n["mac"] for n in snap.get("nodes", [])}
    unit_floors = {}
    for n in snap.get("nodes", []):
        f = floors.get(device_target(normalise_mac(n["mac"]), None))   # pings are keyed as device_id() writes them
        if f and f[0] is not None and f[1] >= placement.MIN_SAMPLES and n.get("online"):
            unit_floors[n["mac"]] = (f[0], unit_names[n["mac"]])
    me = next((c for c in snap.get("clients", []) if my_ip and c.get("ip") == my_ip), None)
    # a client's node in the unit's own spelling of its MAC (the keys above, and what the page matches)
    unit_mac = {m.lower(): m for m in unit_names}
    hearth_unit = unit_mac.get((me.get("node") or "").lower()) if me else None
    roles = (store.topology_at(store.topology_history(conn, now), now) or {}).get("roles") or {}
    unlisted, seen_ids = [], set()
    # one record per device id: the online, most recently seen row decides (a MAC seen at two
    # addresses gives two rows with one id); if that row is skipped, so is the device
    for r in sorted(device_rows(conn), key=lambda r: (-(r[5] or 0), -(r[7] or 0))):
        tid, ip, mac, online, name = r[0], r[1], r[2], r[5], r[8]
        if tid in seen_ids:
            continue
        seen_ids.add(tid)
        # asleep: on the network only as a sleeping card answering ARP - nowhere to place it (#122)
        if not online or r[11] == STATE_ASLEEP or not mac or mac.lower() in listed or mac.lower() in unit_macs:
            continue
        # a unit/client, the router, Hearth. Matching by address means a device that takes one
        # of those addresses isn't drawn here - it is still in the device list; the map is a view
        if ip in taken_ips or (gw and ip == gw) or (my_ip and ip == my_ip):
            continue
        f, n = floors.get(tid, (None, 0))
        res = placement.place(f, n, unit_floors, hearth_unit, (roles.get(tid) or {}).get("role") == "local",
                              names=unit_names)
        unlisted.append({"id": tid, "name": name, "ip": ip, "mac": mac, **res})
    return {"available": True, "ts": snap.get("ts"), "error": err, "nodes": nodes, "devices": devices,
            "findings": findings, "pending_cert": pending, "history": {"bucket_s": bucket, "series": history},
            "self": next((d["id"] for d in devices if my_ip and d["ip"] == my_ip), None), "unlisted": unlisted}


PLACE_MESH, PLACE_TIMING, PLACE_UNKNOWN = "mesh", "timing", "unknown"   # device_places.how


def places_now(view):
    """{device id: (unit MAC or None, how)} for every online device, read from mesh_view's answer -
    the map's own placement, so the record of where devices were can't disagree with the map.
    Listed by the mesh: its unit, 'mesh'; placed by timing: 'timing'; otherwise (None, 'unknown')."""
    if not view.get("available"):
        return {}
    out = {d["id"]: (d["node"], PLACE_MESH) for d in view.get("devices", [])}
    for u in view.get("unlisted", []):
        timed = u.get("placement") == "timing" and u.get("node")
        out[u["id"]] = (u["node"], PLACE_TIMING) if timed else (None, PLACE_UNKNOWN)
    return out


def device_places(conn, device, minutes):
    """Where a device was over the last `minutes`: its place changes in the range, plus the one in
    force at the range's start, oldest first, each {ts, node, node_name, how}. node and node_name
    are None when the place was "location unknown" (how = 'unknown')."""
    since = time.time() - minutes * 60
    rows = conn.execute("""SELECT ts, node, how FROM device_places WHERE device = ? AND ts >= ?
                           UNION SELECT ts, node, how FROM (SELECT ts, node, how FROM device_places
                             WHERE device = ? AND ts < ? ORDER BY ts DESC LIMIT 1)
                           ORDER BY ts""", (device, since, device, since)).fetchall()
    snap = store.get_state(conn, mesh.MESH_STATE_KEY) or {}
    names = {n["mac"]: n.get("name") or n["mac"] for n in snap.get("nodes", [])}
    # a unit that has since left the mesh is named as such, not by a bare MAC
    return {"id": device, "places": [{"ts": ts, "node": node, "how": how,
                                      "node_name": names.get(node, "unit no longer in the mesh") if node else None}
                                     for ts, node, how in rows]}


def mesh_node_of(meshidx, members):
    """The mesh node most of a group's members are on, if at least half are."""
    if not meshidx or not members:
        return None
    counts = {}
    for m in members:
        n = meshidx["where"].get(m)
        if n:
            counts[n] = counts.get(n, 0) + 1
    best = max(counts.items(), key=lambda kv: kv[1], default=(None, 0))
    return meshidx["nodes"].get(best[0]) if best[1] * 2 >= len(members) else None


def _uplink(meshidx, node):
    """How a mesh node reaches the rest of the network, in words."""
    parent = meshidx["nodes"].get(node.get("parent")) if node.get("parent") else None
    if node.get("role") == "main" or not parent:
        return "its cable to the router"
    kind = "cable" if node.get("backhaul") == "wired" else "wireless link"
    return f"its {kind} to {parent.get('name') or 'the main unit'}"


def chain(snap, present, labels, devnames, meshidx=None):
    """Ordered positions from this computer outwards. Each position names the link *into* it,
    which is what gets blamed when that position is the first to spike. When the mesh system
    is read, groups are named after the mesh node they're on and links say what they are."""
    out = []
    snap = snap or {}
    floors = floors_of(snap)
    if snap.get("local"):
        g = snap["local"]
        name = group_name(labels, devnames, g["group"], g["members"], "local")
        node = mesh_node_of(meshidx, g["members"])
        link = "Your local segment (or this computer)"
        if node:
            link = f"{node.get('name')} mesh node or {_uplink(meshidx, node)}"
            if GROUP_PREFIX + str(g["group"]) not in labels:
                name = f"{node.get('name')} (this computer's mesh node)"
        out.append({"pos": POS_LOCAL, "group": g["group"], "name": name, "short": name,
                    "link": link, "targets": g["members"], "mesh": node and node["mac"]})
    for g in snap.get("relays", []):
        name = group_name(labels, devnames, g["group"], g["members"], "relay", floors)
        label = group_label(labels, devnames, g["group"], g["members"], "relay", floors)
        short = group_short(labels, devnames, g["group"], g["members"], "relay", floors)
        node = mesh_node_of(meshidx, g["members"])
        if node and GROUP_PREFIX + str(g["group"]) not in labels:
            name, label, short = f"Relay via {node.get('name')}", node.get("name"), node.get("name")
        out.append({"pos": POS_RELAY, "group": g["group"], "name": name, "short": short,
                    "link": f"Wireless/relay link to {label}", "targets": g["members"],
                    "mesh": node and node["mac"]})
    if TARGET_GATEWAY in present:
        out.append({"pos": POS_GATEWAY, "group": None, "name": "Router",
                    "link": "Link to the router", "targets": [TARGET_GATEWAY]})
    has_isp = TARGET_ISP in present
    if has_isp:
        out.append({"pos": POS_ISP, "group": None, "name": "ISP edge",
                    "link": LINK_ISP, "targets": [TARGET_ISP]})
    inet = sorted(t for t in present if t.startswith(INET_PREFIX))
    if inet:
        out.append({"pos": POS_INTERNET, "group": None, "name": "Internet",
                    "link": LINK_BEYOND if has_isp else LINK_LINE,
                    "targets": inet})
    return out


def branches_of(snap, labels, devnames, meshidx=None):
    floors = floors_of(snap)
    out = []
    for g in (snap or {}).get("branches", []):
        name = group_name(labels, devnames, g["group"], g["members"], "branch", floors)
        short = group_short(labels, devnames, g["group"], g["members"], "branch", floors)
        node = mesh_node_of(meshidx, g["members"])
        if node and GROUP_PREFIX + str(g["group"]) not in labels:
            name, short = f"Branch via {node.get('name')}", node.get("name")
        out.append({"group": g["group"], "name": name, "short": short, "targets": g["members"],
                    "mesh": node and node["mac"]})
    return out


def target_stats(s, base):
    ok = [r for _, r in s if r is not None]
    return {
        "samples": len(s), "lost": len(s) - len(ok),
        "loss_pct": round(100 * (len(s) - len(ok)) / len(s), 2) if s else None,
        "p50": pct(ok, .5), "p95": pct(ok, .95), "p99": pct(ok, .99),
        "max": round(max(ok), 1) if ok else None, "last": s[-1][1] if s else None,
        "spikes": sum(1 for _, r in s if is_spike(r, base)) if ok else 0,
        "jitter": round(statistics.pstdev(ok), 2) if len(ok) > 1 else None,
        "responding": bool(ok),
    }


def _agg(stats_list):
    ts = [x for x in stats_list if x and x["responding"]]
    return {"p95": max((x["p95"] for x in ts if x["p95"] is not None), default=None),
            "loss_pct": max((x["loss_pct"] for x in ts if x["loss_pct"] is not None), default=None),
            "spikes": max((x["spikes"] for x in ts), default=0)}


PORTABLE_KINDS = {"phone", "tablet", "watch", "wearable"}   # the mesh's device types that sleep to save battery


def portable_devices(conn):
    """Device ids the mesh says are phones, tablets or watches - they doze, dropping pings."""
    snap = store.get_state(conn, mesh.MESH_STATE_KEY)
    clients = snap.get("clients", []) if isinstance(snap, dict) else []
    return {device_target(c["mac"], None) for c in clients
            if isinstance(c, dict) and c.get("mac") and c.get("kind") in PORTABLE_KINDS}


def _representative(targets, stats, dozing=()):
    """The steadiest member stands in for a group on the chart - never one that dozes (a phone
    asleep drops pings: its loss isn't the network's, #71). A group of only dozing devices gets
    no line at all."""
    cands = [t for t in targets if stats.get(t) and stats[t]["responding"] and t not in dozing]
    return min(cands, key=lambda t: (stats[t]["loss_pct"] or 0, stats[t]["p50"] or 1e9)) if cands else None


def group_level(targets, stats, names, skip=()):
    """The worst of a group's members' own levels, naming the member, so a dead member makes
    its group bad even when another member is healthy. A member not pinged in the window at
    all is unknown and doesn't lower the group (Hearth not having pinged it says nothing);
    neither do members in `skip` - devices that answer erratically (phones dozing), which the
    timing analysis marks unstable."""
    results = []
    for t in targets:
        if t in skip:
            continue
        r = lv.link_level(stats.get(t))
        results.append(lv.result(r["level"], f"{names.get(t, t)}: {r['why']}"))
    return lv.worst_of(results)


def path_label(snap, labels, devnames, meshidx=None):
    """How this computer reaches the router. The mesh system's own answer when it's read
    (e.g. "Office → wireless → Bedroom → router"), else what the timing inference found."""
    node = meshidx and meshidx["nodes"].get(meshidx.get("self"))
    if node:
        hops, seen = [node.get("name") or node["mac"]], {node["mac"]}
        while node.get("parent") and node["parent"] not in seen:
            parent = meshidx["nodes"].get(node["parent"])
            if not parent:
                break
            hops += ["cable" if node.get("backhaul") == "wired" else "wireless", parent.get("name") or parent["mac"]]
            seen.add(parent["mac"])
            node = parent
        return "Via " + " → ".join(hops) + " → router"
    relays = (snap or {}).get("relays", [])
    if not relays:
        return "Direct to the router"
    floors = floors_of(snap)
    return "Via " + ", ".join(group_label(labels, devnames, g["group"], g["members"], "relay", floors)
                              for g in relays)


def summary(conn, minutes):
    now = time.time()
    since = now - minutes * 60
    by = fetch_raw(conn, since)
    base = baselines(by)
    labels, devnames = store.labels(conn), device_names(conn)
    meshidx = mesh_index(conn)
    snap = store.topology_at(store.topology_history(conn, now), now)
    stats = {t: target_stats(s, base.get(t)) for t, s in by.items()}

    member_names = {**devnames, TARGET_GATEWAY: "Router", TARGET_ISP: "ISP edge",
                    **{t: t[len(INET_PREFIX):] for t in stats if t.startswith(INET_PREFIX)}}
    dozing = {t for t, r in ((snap or {}).get("roles") or {}).items() if r.get("role") == "unstable"}
    # devices that sleep to save battery drop pings by design: the mesh says which (#71)
    asleep_by_design = portable_devices(conn)
    hops = []
    for p in chain(snap, set(by), labels, devnames, meshidx):
        hops.append({**p, **_agg([stats.get(t) for t in p["targets"]]),
                     **group_level(p["targets"], stats, member_names, dozing),
                     "targets": [t for t in p["targets"] if t in stats]})
    branches = [{**b, **_agg([stats.get(t) for t in b["targets"]]), **group_level(b["targets"], stats, member_names, dozing)}
                for b in branches_of(snap, labels, devnames, meshidx)]

    roles = (snap or {}).get("roles", {})
    where = {}
    for h in hops:
        for t in h["targets"]:
            where[t] = h["name"]
    for b in branches:
        for t in b["targets"]:
            where[t] = b["name"]
    devices = []
    for t, s in stats.items():
        if not t.startswith("dev:"):
            continue
        r = roles.get(t, {})
        devices.append({"id": t, "name": devnames.get(t, t), "group": where.get(t), "role": r.get("role"),
                        "evidence": {k: r.get(k) for k in ("side", "floor", "shared", "spikes", "confident")},
                        **s})
    devices.sort(key=lambda d: (d["group"] is None, d["group"] or "", d["name"]))
    for d in devices:
        d.update(lv.link_level(d))

    chart = []
    for h in hops:
        if h["pos"] == POS_INTERNET:
            chart += [{"id": t, "label": t[len(INET_PREFIX):]} for t in h["targets"]]
        else:
            rep = _representative(h["targets"], stats, dozing | asleep_by_design)
            if rep:
                chart.append({"id": rep, "label": h["name"] if h["group"] is None else f"{h['name']} ({devnames.get(rep, rep)})"})
    for b in branches:
        rep = _representative(b["targets"], stats, dozing | asleep_by_design)
        if rep:
            chart.append({"id": rep, "label": f"{b['name']} ({devnames.get(rep, rep)})"})

    return {"hops": hops, "branches": branches, "devices": devices, "chart": chart,
            "core": {t: {**stats[t], **lv.link_level(stats[t])} for t in stats
                     if t in (TARGET_GATEWAY, TARGET_ISP) or t.startswith(INET_PREFIX)},
            "path": path_label(snap, labels, devnames, meshidx), "layout_known": snap is not None,
            "path_changes": conn.execute("SELECT COUNT(*) FROM events WHERE kind=? AND ts >= ?",
                                         (EV_PATH, since)).fetchone()[0],
            "minutes": minutes, "now": now}


def series(conn, minutes, points=360):
    since = time.time() - minutes * 60
    bucket = max(1, int(minutes * 60 / points))
    if bucket >= 60 or minutes * 60 > store.RAW_HOURS * 3600:
        # long windows read the 1-minute rollups: thousands of rows instead of millions
        bucket = max(60, bucket // 60 * 60)
        rows = conn.execute(
            """SELECT target, CAST(ts / ? AS INTEGER) * ? AS b,
                      SUM(avg * (n - lost)) / NULLIF(SUM(n - lost), 0), MAX(max), SUM(lost), SUM(n)
               FROM pings_1m WHERE ts >= ? GROUP BY target, b ORDER BY b""",
            (bucket, bucket, since)).fetchall()
    else:
        bucket = max(bucket, 5)  # devices are polled every 5 s
        rows = conn.execute(
            """SELECT target, CAST(ts / ? AS INTEGER) * ? AS b,
                      AVG(rtt), MAX(rtt), SUM(CASE WHEN rtt IS NULL THEN 1 ELSE 0 END), COUNT(*)
               FROM pings WHERE ts >= ? GROUP BY target, b ORDER BY b""",
            (bucket, bucket, since)).fetchall()
    out = {}
    for name, b, avg, mx, lost, n in rows:
        out.setdefault(name, []).append([b, round(avg, 2) if avg is not None else None,
                                         round(mx, 2) if mx is not None else None,
                                         round(lost / n, 3)])
    return {"bucket_s": bucket, "series": out}


def cluster_window(conn, since, until):
    """Spike clusters ("incidents") in [since, until), oldest first, and the raw samples they
    came from. Simultaneous spikes are grouped and the link into the first position (closest
    to this computer) that spiked is blamed, using the layout in force at the time."""
    by = fetch_raw(conn, since, until)
    base = baselines(by)
    labels, devnames = store.labels(conn), device_names(conn)
    meshidx = mesh_index(conn)
    history = store.topology_history(conn, since)
    # a target that never answered in the window is left out (a device that's off says nothing
    # about the network) - except the router and the internet targets: for them silence is the
    # signal, e.g. an outage longer than the window
    core = {n for n in by if n == TARGET_GATEWAY or n.startswith(INET_PREFIX)}
    responding = {n for n, s in by.items() if any(r is not None for _, r in s)} | core
    single_inet = [inet_target(ip) for ip in CFG["internet_targets"]]
    single_inet = single_inet[0] if len(single_inet) == 1 else None

    spike_secs = {}  # int second -> {target: rtt}
    for name, s in by.items():
        if name not in responding:
            continue
        for ts, rtt in s:
            if is_spike(rtt, base.get(name)):
                spike_secs.setdefault(int(ts), {})[name] = rtt

    incs, cur = [], None
    for sec in sorted(spike_secs):
        if cur and sec - cur["end"] <= 6:  # devices are sampled every 5 s
            cur["end"] = sec
            cur["hits"].append(spike_secs[sec])
        else:
            cur = {"start": sec, "end": sec, "hits": [spike_secs[sec]]}
            incs.append(cur)

    # in time order, so each incident finds its rows by binary search: a scan per incident was
    # quadratic (a day has thousands of incidents and ~86 000 traffic rows)
    sweeps = conn.execute("SELECT start, end FROM sweeps WHERE end >= ? ORDER BY start", (since - 60,)).fetchall()
    sweep_starts = [s for s, _ in sweeps]
    sweep_end_max = list(itertools.accumulate((e for _, e in sweeps), max))  # latest end among sweeps so far
    side_ev = conn.execute("SELECT ts, detail FROM events WHERE (kind LIKE 'wifi_%' OR kind IN (?, 'isp_path')) "
                           "AND ts >= ? ORDER BY ts", (EV_PATH, since - 300)).fetchall()
    side_ts = [ts for ts, _ in side_ev]
    traffic = conn.execute("SELECT ts, rx_mbps, tx_mbps FROM traffic WHERE ts >= ? ORDER BY ts",
                           (since - 60,)).fetchall()
    traffic_ts = [ts for ts, _, _ in traffic]
    # per-device internet use from the router; each reading covers the minute or so before it
    used = conn.execute("SELECT ts, mac, dur, rx, tx FROM usage WHERE ts >= ? ORDER BY ts, mac",
                        (since,)).fetchall()
    usage_name = _usage_namer(conn) if used else None
    times = {t: [ts for ts, _ in s] for t, s in by.items()}  # already in time order
    chains = {}

    def active_at(lo, hi):
        """Targets with at least one sample in [lo, hi]: an incident is judged only on what was
        actually being measured then (e.g. not on an ISP edge that had stopped answering)."""
        return {t for t, ts in times.items() if bisect.bisect_left(ts, lo) < bisect.bisect_right(ts, hi)}

    result = []
    for inc in incs:
        tstats = {}
        for hit in inc["hits"]:
            for n, r in hit.items():
                st = tstats.setdefault(n, {"count": 0, "lost": 0, "max": 0})
                st["count"] += 1
                if r is None:
                    st["lost"] += 1
                else:
                    st["max"] = max(st["max"], r)
        snap = store.topology_at(history, inc["start"])
        present = active_at(inc["start"] - 6, inc["end"] + 6)
        key = (snap["_ts"] if snap else None, frozenset(t for t in present if not t.startswith("dev:")))
        if key not in chains:
            ch = chain(snap, present, labels, devnames, meshidx)
            pos_of = {t: i for i, p in enumerate(ch) for t in p["targets"]}
            branch_of = {t: b["name"] for b in branches_of(snap, labels, devnames, meshidx) for t in b["targets"]}
            chains[key] = (ch, pos_of, branch_of)
        ch, pos_of, branch_of = chains[key]
        on_path = {n: st for n, st in tstats.items() if n in pos_of}
        positions_with_data = sorted({pos_of[t] for t in present & set(pos_of) if t in responding})

        if not on_path:
            names = sorted({branch_of[n] for n in tstats if n in branch_of})
            if names:
                verdict = f"Branch only: {', '.join(names)} (not on this computer's path)"
            else:
                verdict = f"Blip on {devnames.get(next(iter(tstats)), next(iter(tstats)))} only"
            confident, blip, lo = False, True, None
        else:
            spiked = sorted({pos_of[n] for n in on_path})
            lo = spiked[0]
            downstream = [p for p in positions_with_data if p >= lo]
            last = positions_with_data[-1] if positions_with_data else lo
            # one target alone spiking is a blip - unless it's the only internet target configured,
            # which then carries the internet's whole story (e.g. a dark run with one target)
            alone = len(on_path) == 1 and next(iter(on_path)) != single_inet
            blip = alone or (spiked == [lo] and ch[lo]["pos"] == POS_ISP and lo != last)
            if blip:
                who = next(iter(on_path))
                verdict = (f"Blip on {devnames.get(who, who)} only (that device, not the network)"
                           if ch[lo]["pos"] != POS_ISP else "ISP edge only (often just ICMP rate limiting)")
                confident = False
            elif all(p in spiked for p in downstream):
                verdict = f"Fault at: {ch[lo]['link']}"
                confident = len(downstream) > 1 or lo == last
            elif spiked == [last]:
                verdict = f"Fault at: {ch[last]['link']}"
                confident = True
            else:
                verdict = "Unclear - " + ", ".join(ch[p]["link"] for p in spiked)
                confident = False
            if confident and ch[lo]["pos"] in LINE_POSITIONS:
                lost = sum(st["lost"] for st in on_path.values())
                # queuing on the line shows at the ISP edge first; beyond it, it's the ISP's network
                line = ch[lo]["pos"] == POS_ISP or not any(p["pos"] == POS_ISP for p in ch)
                verdict += (" (packets lost)" if lost else
                            " (delay only, no loss: traffic queuing on the line)" if line else " (delay only, no loss)")

        # a sweep overlaps (2 s slack) if one starting by end+2 is still running at start-2
        k = bisect.bisect_right(sweep_starts, inc["end"] + 2)
        during_sweep = k > 0 and sweep_end_max[k - 1] >= inc["start"] - 2
        if during_sweep:
            verdict = "Ignored: device scan running (" + verdict + ")"
            confident = False
        context = [d for _, d in side_ev[bisect.bisect_left(side_ts, inc["start"] - 90):
                                         bisect.bisect_right(side_ts, inc["end"] + 30)]]
        tr = [(rx, tx) for _, rx, tx in traffic[bisect.bisect_left(traffic_ts, inc["start"] - 4):
                                                bisect.bisect_right(traffic_ts, inc["end"] + 2)]]
        if tr:
            context.append(f"This computer's network port: peak {max(r for r, _ in tr):.1f} Mb/s in, "
                           f"{max(t for _, t in tr):.1f} Mb/s out")
        if used:
            busy = busiest_during(used, inc["start"], inc["end"], usage_name)
            if busy:
                context.append(busy)
        result.append({
            "blip": blip, "during_sweep": during_sweep, "context": context,
            "start": inc["start"], "end": inc["end"], "duration_s": inc["end"] - inc["start"] + 1,
            "verdict": verdict, "confident": confident,
            "fault": ch[lo]["link"] if confident and lo is not None else None,
            "targets": {devnames.get(n, n.replace(INET_PREFIX, "")): v for n, v in tstats.items()},
        })
    return result, by


def usual_window_s():
    """How far back "usual" looks: the raw ping retention (raw_retention_hours, 48 h by default),
    since hours are worked out from raw pings."""
    return store.RAW_HOURS * 3600


def dark_bridge_s():
    """Unmeasured seconds tolerated inside a dark run: about one ping cycle (interval plus
    timeout), the most a pinger can skip between two probes."""
    return max(0, math.ceil(float(CFG["core_interval_s"]) + int(CFG["ping_timeout_ms"]) / 1000) - 1)


def episode_window(conn, since, until):
    """Episodes (newest first), the momentary spike count, and the clusters (oldest first) for
    [since, until)."""
    clusters, by = cluster_window(conn, since, until)
    inet = [inet_target(ip) for ip in CFG["internet_targets"]]
    states = ep.second_states(by, inet, TARGET_GATEWAY)
    episodes, momentary = ep.build(clusters, states, len(inet) == 1, dark_bridge_s())
    episodes = during_speedtests(episodes, speedtest.windows(conn, since, until))
    episodes = with_dns_context(conn, episodes, since, until)
    episodes.reverse()
    return {"episodes": episodes, "momentary": momentary, "clusters": clusters}


DNS_EDGE_S = 60           # the DNS check runs once a minute: look a minute either side


def with_dns_context(conn, episodes, since, until):
    """An episode while the router's DNS wasn't answering, or was slow, says so (#101): a site
    that "won't load" is often DNS, not the line."""
    gw = _gateway_ip(conn)
    if not episodes or not gw:
        return episodes
    rows = conn.execute("SELECT ts, ms, rcode FROM dns_1m WHERE resolver = ? AND ts >= ? AND ts < ?",
                        (gw, since - DNS_EDGE_S, until + DNS_EDGE_S)).fetchall()
    if not rows:
        return episodes
    rows.sort()
    times = [r[0] for r in rows]
    out = []
    for e in episodes:   # each episode looks only at its own minutes of the sorted rows
        lo, hi = bisect.bisect_left(times, e["start"] - DNS_EDGE_S), bisect.bisect_right(times, e["end"] + DNS_EDGE_S)
        near = [(ms, rcode) for _, ms, rcode in rows[lo:hi]]
        answered = [ms for ms, rcode in near if rcode == 0 and ms is not None]
        note = None
        if near and len(answered) < len(near):
            note = "The router's DNS didn't answer then: sites may not have opened"
        elif answered and pct(answered, 0.5) > lv.DNS_SLOW_FAIR:
            note = f"The router's DNS was slow then ({pct(answered, 0.5):.0f} ms an answer)"
        out.append({**e, "context": [*(e.get("context") or []), note]} if note else e)
    return out


SPEEDTEST_EDGE_S = 15     # a test's lag can trail its end by a few seconds


def during_speedtests(episodes, windows):
    """A speed test fills the line on purpose: a slow spell inside one isn't the line's fault and
    is dropped; anything worse (a loss, an outage) is kept, saying it happened during a test.
    Tests are capped (speedtest.MAX_PER_HOUR, a minute apart), so at most a few short windows an
    hour can be taken out of the record - repeated tests can't hide the line's real slow spells."""
    if not windows:
        return episodes
    out = []
    for e in episodes:
        inside = [w for w in windows if e["start"] >= w[0] - SPEEDTEST_EDGE_S and e["end"] <= w[1] + SPEEDTEST_EDGE_S]
        touches = inside or [w for w in windows if e["start"] < w[1] + SPEEDTEST_EDGE_S and e["end"] > w[0]]
        if inside and e.get("kind") == ep.KIND_SLOW:
            continue
        if touches:
            e = {**e, "context": [*(e.get("context") or []), "During a speed test (the test fills the line on purpose)"]}
        out.append(e)
    return out


EPISODE_EDGE_S = ep.EPISODE_GAP_S * 3  # an hour is judged with this much either side, so episodes crossing it are whole
MONITORED_SHARE = 0.9                  # an hour counts towards "usual" only if pinged this much of the time


def _monitored(conn, hour):
    """Were the internet targets pinged in at least MONITORED_SHARE of this hour's seconds?"""
    inet = [inet_target(ip) for ip in CFG["internet_targets"]]
    if not inet:
        return False
    marks = ",".join("?" * len(inet))
    n = conn.execute(f"SELECT COUNT(DISTINCT CAST(ts AS INTEGER)) FROM pings WHERE ts >= ? AND ts < ? "
                     f"AND target IN ({marks})", (hour, hour + 3600, *inet)).fetchone()[0]
    # pinged every core_interval_s: at 2 s, at most half the seconds can have a sample
    return n >= MONITORED_SHARE * 3600 / max(1.0, float(CFG["core_interval_s"]))


def fill_spike_hours(conn, now, max_hours=4, skip=None):
    """Work out up to max_hours missing rows of spike_hours (newest first) and store them;
    returns how many were written. Background only: requests just read the table. An hour
    is stored once it's fully past, including its edge window, and only if it was monitored;
    a stored row is final. A real cluster near the window's edge makes the hour uncertain
    (stored as bad, so left out of usual). An hour whose processing raises is added to skip,
    so one bad hour can't block the rest."""
    first = conn.execute("SELECT MIN(ts) FROM pings").fetchone()[0]
    if first is None:
        return 0
    lo = max(int(now - usual_window_s()), int(first)) // 3600 * 3600 + 3600
    hi = int(now - 3600 - EPISODE_EDGE_S) // 3600 * 3600        # newest hour that is fully past
    have = {h for (h,) in conn.execute("SELECT hour FROM spike_hours WHERE hour >= ?", (lo,))}
    written = 0
    for h in range(hi, lo - 1, -3600):
        if written >= max_hours:
            break
        if h in have or (skip is not None and h in skip):
            continue
        try:
            if not _monitored(conn, h):
                if skip is not None:
                    skip.add(h)  # a past hour doesn't become monitored later: don't check it again
                continue
        except Exception:
            if skip is not None:
                skip.add(h)  # this hour's data trips something: don't let it block the others
            raise
        lo_w, hi_w = h - EPISODE_EDGE_S, h + 3600 + EPISODE_EDGE_S
        try:
            win = episode_window(conn, lo_w, hi_w)
        except Exception:
            if skip is not None:
                skip.add(h)
            raise
        real = [c for c in win["clusters"] if not c["blip"] and not c["during_sweep"]]
        # a real cluster near either edge may belong to an episode reaching outside the
        # window, which would then be misjudged: count the hour as uncertain (left out)
        edge = any(c["start"] < lo_w + ep.EPISODE_GAP_S or c["end"] >= hi_w - ep.EPISODE_GAP_S for c in real)
        bad = edge or any(e["level"] == ep.LEVEL_BAD for e in win["episodes"] if e["start"] < h + 3600 and e["end"] >= h)
        spikes = sum(1 for c in real if h <= c["start"] < h + 3600
                     and not any(e["start"] <= c["start"] <= e["end"] for e in win["episodes"]))
        conn.execute("INSERT OR REPLACE INTO spike_hours VALUES (?,?,?)", (h, spikes, int(bad)))
        conn.commit()  # per hour: a later failure doesn't lose the hours already done
        written += 1
    return written


def spike_usual(conn, now):
    """The usual number of momentary spikes per hour, from stored hours (read-only)."""
    rows = conn.execute("SELECT hour, spikes, bad FROM spike_hours WHERE hour >= ?",
                        (now - usual_window_s(),)).fetchall()
    return ep.usual_per_hour(rows)


# --- episodes kept: stored once final, so ranges longer than the raw data still have them
LIVE_S = 6 * 3600                          # a long range builds only this recent part live
EPISODE_FINAL_S = 3 * ep.EPISODE_GAP_S     # an episode this long over can't be joined any more
# state row of the store loop: {last_ok, last_error, since}; since = failing since (None while healthy)
EPISODES_STORE_KEY = "episodes_store"
HEARTH_STARTED = time.time()               # the store loop must have run since, for history to be complete


def _overlaps(a, b):
    return a["start"] <= b["end"] and b["start"] <= a["end"]


SLOW_RULE_KEY = "slow_rule"   # state: the SLOW_MIN_S stored slow spells were last checked against


def reclassify_stored_slow(conn):
    """Once per change of episodes.SLOW_MIN_S: drop stored slow spells that no longer qualify
    (under SLOW_MIN_S seconds in clusters and fewer than three clusters) - from their stored
    parts, so the timeline, report card and digest don't keep the old rule's noise for 400
    days. Only "slow" ones: an outage or a problem doesn't depend on this rule. Returns how
    many were dropped."""
    if store.get_state(conn, SLOW_RULE_KEY) == ep.SLOW_MIN_S:
        return 0
    drop = []
    for start, data in conn.execute("SELECT start, data FROM episodes WHERE kind = ?", (ep.KIND_SLOW,)):
        try:
            d = json.loads(data)
            # seconds in clusters, by merging the parts' intervals (never one set entry a second:
            # a damaged part with a huge end mustn't exhaust memory at start)
            busy, last = 0, None
            for a, b in sorted((int(p["start"]), int(p["end"])) for p in d.get("parts") or []):
                if last is not None and a <= last:
                    a = last + 1
                if b >= a:
                    busy += b - a + 1
                last = b if last is None else max(last, b)
            if busy < ep.SLOW_MIN_S and int(d.get("clusters") or 0) < 3:
                drop.append(start)
        except (ValueError, TypeError, KeyError):   # a damaged record is left as it is
            continue
    conn.executemany("DELETE FROM episodes WHERE start = ? AND kind = ?", [(s, ep.KIND_SLOW) for s in drop])
    if drop:   # digests counted the old rule's slow spells: last week's is rebuilt (digest.due)
        conn.execute("DELETE FROM digests")
    store.set_state(conn, SLOW_RULE_KEY, ep.SLOW_MIN_S)
    return len(drop)


def store_episodes(conn, now):
    """Store every final episode in the raw data (background only); returns how many were
    written. Episodes never overlap, so overlap is their identity: a complete episode replaces
    the records it overlaps that start at or after it (a repeat write of itself, or a later-
    starting truncated record), never one starting earlier; a truncated one - starting so near the
    raw data's start that its beginning may be missing - is written only if nothing overlaps it.
    So a shorter view of an episode never replaces a longer one."""
    lo = now - usual_window_s()
    win = episode_window(conn, lo, now + 1)
    written = 0
    for e in win["episodes"]:
        if e["end"] > now - EPISODE_FINAL_S:
            continue   # not final: a cluster could still join it
        # decided from this build's own window (the same <= as grouping): a later build never
        # sees more of an episode, since the window only slides forward
        truncated = e["start"] <= lo + ep.EPISODE_GAP_S
        overlap = "FROM episodes WHERE start <= ? AND end >= ?"
        if truncated:
            if conn.execute(f"SELECT 1 {overlap} LIMIT 1", (e["end"], e["start"])).fetchone():
                continue
        else:
            # a stored record starting earlier already covers more of it: never replace a longer
            # view with a shorter one
            if conn.execute(f"SELECT 1 {overlap} AND start < ? LIMIT 1", (e["end"], e["start"], e["start"])).fetchone():
                continue
            # what's left overlapping starts at or after it: by the no-overlap invariant, a repeat
            # write of itself or a truncated record of it - never a different episode ending later
            conn.execute(f"DELETE {overlap}", (e["end"], e["start"]))
        conn.execute("INSERT INTO episodes VALUES (?,?,?,?,?,?)",
                     (e["start"], e["end"], e["kind"], e["level"], int(truncated),
                      json.dumps({**e, "truncated": truncated})))
        written += 1
    return written


def history_state(conn, now):
    """(complete, error) for stored episodes: complete once the store loop has succeeded since
    Hearth started and recently enough that nothing before the live part can be missing."""
    st = store.get_state(conn, EPISODES_STORE_KEY) or {}
    last_ok = st.get("last_ok") if isinstance(st, dict) else None
    ok = isinstance(last_ok, (int, float)) and last_ok >= HEARTH_STARTED and now - last_ok <= LIVE_S - 3600
    if ok:
        return True, None
    err = st.get("last_error") if isinstance(st, dict) else None
    return False, err or "slowdowns and outages from before the last few hours are still being saved"


def incidents(conn, minutes):
    """Spike clusters (incidents) and the episodes they form, over the last `minutes`.

    A range reaching back before B (the start of the hour about LIVE_S ago) reads stored episodes
    for the time before B and builds only from B on live - fast, and not limited to the raw data.
    A live episode overlapping a stored one is a fragment of it and is dropped; one starting
    before B that overlaps nothing stored is still going on and is shown, marked truncated.
    Momentary spikes before B come from stored whole hours; the cluster list starts at B."""
    now = time.time()
    since = now - minutes * 60
    b = int((now - LIVE_S) // 3600 * 3600)
    extra = {}
    if since >= b:
        win = episode_window(conn, since, now + 1)
        episodes, clusters, momentary = win["episodes"], win["clusters"], win["momentary"]
    else:
        # bounds and kind only: a 400-day range can hold tens of thousands of stored episodes,
        # and only the newest 300 are returned in full
        stored = [{"start": s, "end": e, "kind": k, "level": lv_, "_stored": True} for s, e, k, lv_ in conn.execute(
            "SELECT start, end, kind, level FROM episodes WHERE end >= ? AND start < ? ORDER BY start", (since, b))]
        win = episode_window(conn, b - ep.EPISODE_GAP_S, now + 1)
        near = [s for s in stored if s["end"] >= b - ep.EPISODE_GAP_S]   # only these can meet the live build
        live = []
        for e in win["episodes"]:
            if any(_overlaps(e, s) for s in near):
                continue
            live.append({**e, "truncated": True} if e["start"] < b else e)
        episodes = sorted(stored + live, key=lambda e: e["start"], reverse=True)
        # the full record for the stored ones that are listed
        want = [e["start"] for e in episodes[:300] if e.get("_stored")]
        full = {}
        for i in range(0, len(want), 500):
            chunk = want[i:i + 500]
            full.update((s, json.loads(d)) for s, d in conn.execute(
                f"SELECT start, data FROM episodes WHERE start IN ({','.join('?' * len(chunk))})", chunk))
        episodes = [full.get(e["start"], e) if e.get("_stored") else e for e in episodes[:300]] + episodes[300:]
        episodes = [{k: v for k, v in e.items() if k != "_stored"} for e in episodes]
        clusters = [c for c in win["clusters"] if c["start"] >= b]
        first_hour = math.ceil(since / 3600) * 3600
        hours, spikes = conn.execute("SELECT COUNT(*), COALESCE(SUM(spikes), 0) FROM spike_hours "
                                     "WHERE hour >= ? AND hour + 3600 <= ?", (first_hour, b)).fetchone()
        momentary = spikes + sum(1 for c in clusters if c.get("momentary"))
        complete, error = history_state(conn, now)
        extra = {"incidents_since": b, "spikes_since": first_hour, "spikes_hours_counted": hours,
                 "history_complete": complete, "history_error": error}
    result = list(reversed(clusters))
    blame = {}
    for r in result:
        if r["confident"]:
            blame[r["fault"]] = blame.get(r["fault"], 0) + 1
    real = [r for r in result if not r["blip"] and not r["during_sweep"]]
    noise = [r for r in result if r["blip"] or r["during_sweep"]]
    return {"incidents": real[:300], "blips": noise[:300],
            "total": len(real), "blip_total": len(noise), "blame": blame,
            "episodes": episodes[:300], "episode_total": len(episodes),
            # over all episodes, not just the 300 listed (wording from episodes.KIND_NAMES)
            "episode_breakdown": ep.breakdown(episodes), "episode_level": ep.worst_level(episodes),
            "momentary": [r for r in real if r.get("momentary")][:300],
            "spikes_total": momentary, "spikes_usual_per_hour": spike_usual(conn, now), **extra}


MB = 1e6
TOP_DEVICES = 6  # shown one by one on the traffic chart; the rest are summed


def _usage_namer(conn):
    """mac -> display name: your label, Hearth's own name for the device, the router's name for
    it, else "maker · MAC" (e.g. this computer, which Hearth doesn't list as a device)."""
    devnames, labels, routed = device_names(conn), store.labels(conn), router_names(conn)

    def name(mac):
        tid = device_target(mac, None)
        return labels.get(tid) or devnames.get(tid) or routed.get(mac) or fallback_name(net.vendor(mac), mac)
    return name


def _local_midnight(now):
    t = time.localtime(now)
    return time.mktime((t.tm_year, t.tm_mon, t.tm_mday, 0, 0, 0, 0, 0, -1))


def _detailed(since, now):
    """Per-reading rows still cover `since` (they're kept DETAIL_DAYS): exact totals."""
    return since >= now - store.DETAIL_DAYS * 86400


def usage_totals(conn, since, now=None):
    """(download bytes, upload bytes) for everyone since `since`. Exact while the per-reading
    rows cover it; beyond that, whole hours from the hourly table (up to an hour extra)."""
    if _detailed(since, now or time.time()):
        sql, arg = "FROM usage WHERE ts >= ?", since
    else:
        sql, arg = "FROM usage_1h WHERE ts >= ?", int(since // 3600 * 3600)
    rx, tx = conn.execute(f"SELECT COALESCE(SUM(rx),0), COALESCE(SUM(tx),0) {sql}", (arg,)).fetchone()
    return rx, tx


_ip_cache, _ip_lock = {"ts": 0.0, "ip": None}, threading.Lock()


def _my_ip(ttl=60):
    """This machine's LAN address, re-checked at most once a minute (it rarely changes, and
    /api/usage is polled every few seconds). Locked: request handlers run in parallel."""
    with _ip_lock:
        now = time.time()
        if now - _ip_cache["ts"] > ttl:
            _ip_cache.update(ts=now, ip=net.local_ip())
        return _ip_cache["ip"]


def usage_now(conn, now=None):
    """Speeds from the latest router reading, if it's recent: {ts, down_mbps, up_mbps, by_mac}."""
    now = now or time.time()
    last = conn.execute("SELECT MAX(ts) FROM usage").fetchone()[0]
    if last is None or now - last > 3 * router.poll_interval_s():
        return None
    by_mac = {mac: (rx * 8 / dur / MB, tx * 8 / dur / MB)
              for mac, dur, rx, tx in conn.execute("SELECT mac, dur, rx, tx FROM usage WHERE ts = ?", (last,))
              if dur > 0}
    return {"ts": last, "down_mbps": round(sum(d for d, _ in by_mac.values()), 2),
            "up_mbps": round(sum(u for _, u in by_mac.values()), 2), "by_mac": by_mac}


def usage(conn, minutes):
    """Internet traffic per device, read from the router: right now, over the window (totals,
    peaks, a chart series), and today / this week. Router traffic is internet traffic: copies
    between devices at home don't pass through the router."""
    now = time.time()
    since = now - minutes * 60
    name = _usage_namer(conn)
    known = conn.execute("SELECT COUNT(*) FROM router_clients").fetchone()[0]
    out = {"available": known > 0, "interval_s": router.poll_interval_s(), "minutes": minutes, "now": now,
           "error": store.get_state(conn, router.ERROR_STATE_KEY)}  # {since, error} while unreadable
    if not known:
        return out

    cur = usage_now(conn, now)
    out["current"] = None if not cur else {
        "ts": cur["ts"], "down_mbps": cur["down_mbps"], "up_mbps": cur["up_mbps"],
        "devices": sorted(({"id": device_target(m, None), "name": name(m), "down_mbps": round(d, 2),
                            "up_mbps": round(u, 2)} for m, (d, u) in cur["by_mac"].items() if d + u >= 0.01),
                          key=lambda x: -(x["down_mbps"] + x["up_mbps"]))}

    # per-device totals: exact (with peaks) while per-reading rows cover the window, else hourly
    if _detailed(since, now):
        per = {mac: [rx, tx, pd, pu] for mac, rx, tx, pd, pu in conn.execute(
            """SELECT mac, SUM(rx), SUM(tx), MAX(rx * 8.0 / dur / ?), MAX(tx * 8.0 / dur / ?)
               FROM usage WHERE ts >= ? AND dur > 0 GROUP BY mac""", (MB, MB, since))}
    else:
        per = {mac: [rx, tx, None, None] for mac, rx, tx in conn.execute(
            "SELECT mac, SUM(rx), SUM(tx) FROM usage_1h WHERE ts >= ? GROUP BY mac",
            (int(since // 3600 * 3600),))}
    # chart: per reading up to a day, hourly (or daily) beyond
    if minutes <= 1440:
        step = max(60, int(router.poll_interval_s()))
        bucket = max(step, int(minutes * 60 / 120) // step * step)
        table, lo = "usage", since
    else:
        bucket = 3600 if minutes <= 14 * 1440 else 86400
        table, lo = "usage_1h", int(since // 3600 * 3600)
    rows = conn.execute(
        f"SELECT CAST(ts / ? AS INTEGER) * ? AS b, mac, SUM(rx), SUM(tx) FROM {table} WHERE ts >= ? "
        "GROUP BY b, mac", (bucket, bucket, lo)).fetchall()
    # the busiest devices, judged on exactly what is charted
    charted = {}
    for _, mac, rx, tx in rows:
        charted[mac] = charted.get(mac, 0) + rx + tx
    top = sorted(charted, key=lambda m: -charted[m])[:TOP_DEVICES]
    pts, by_dev = {}, {}
    for b, mac, rx, tx in rows:
        t = pts.setdefault(b, [0, 0])
        t[0] += rx
        t[1] += tx
        d = by_dev.setdefault(mac if mac in top else None, {}).setdefault(b, [0, 0])
        d[0] += rx
        d[1] += tx

    def rate(v):  # bytes per bucket -> average Mb/s
        return round(v * 8 / bucket / MB, 3)

    # this computer, as the router knows it: where the map starts
    my_ip = _my_ip()
    me = conn.execute("SELECT mac FROM router_clients WHERE ip = ? ORDER BY online DESC, last_seen DESC LIMIT 1",
                      (my_ip,)).fetchone() if my_ip else None
    out["self_id"] = device_target(me[0], None) if me else None
    out["window"] = {
        "down_bytes": sum(p[0] for p in per.values()), "up_bytes": sum(p[1] for p in per.values()),
        "devices": sorted(({"id": device_target(m, None), "name": name(m), "down_bytes": p[0], "up_bytes": p[1],
                            "peak_down_mbps": None if p[2] is None else round(p[2], 2),
                            "peak_up_mbps": None if p[3] is None else round(p[3], 2)}
                           for m, p in per.items()), key=lambda x: -(x["down_bytes"] + x["up_bytes"]))}
    out["series"] = {
        "bucket_s": bucket,
        "points": [[b, rate(v[0]), rate(v[1])] for b, v in sorted(pts.items())],
        # the busiest devices one by one, the rest together (id None): for a stacked chart
        "by_device": [{"id": device_target(m, None) if m else None, "name": name(m) if m else None,
                       "points": [[b, rate(v[0]), rate(v[1])] for b, v in sorted(by_dev[m].items())]}
                      for m in top + [None] if m in by_dev]}
    today, week = usage_totals(conn, _local_midnight(now), now), usage_totals(conn, now - 7 * 86400, now)
    out["today"] = {"down_bytes": today[0], "up_bytes": today[1]}
    out["week"] = {"down_bytes": week[0], "up_bytes": week[1]}
    # when recording began: totals for periods that started earlier are partial, and say so
    # (per-reading rows are exact; once they've aged out, the oldest hourly bucket is close enough)
    first = conn.execute("SELECT MIN(ts - dur) FROM usage").fetchone()[0]
    first_h = conn.execute("SELECT MIN(ts) FROM usage_1h").fetchone()[0]
    if first is None or (first_h is not None and first_h < first - 3600):
        first = first_h
    out["recording_since"] = first if first is not None else now
    return out


LIVE_FRESH_S = 10          # a ping result older than this says nothing about now
_namer_cache = {"ts": 0.0, "fn": None}


def _live_namer(conn, ttl=60):
    """_usage_namer() reads every device name; /api/live is asked every 2 s per open page, so
    the name lookup is reused for a minute."""
    now = time.time()
    if _namer_cache["fn"] is None or now - _namer_cache["ts"] > ttl:
        _namer_cache.update(ts=now, fn=_usage_namer(conn))
    return _namer_cache["fn"]


def live_view(conn):
    """The figures the page shows in real time while it's being viewed. Cheap by design - the
    latest pings from memory, the router's latest reading (one indexed lookup), this computer's
    latest sample - since it's asked for every couple of seconds."""
    now = time.time()
    pings = live.latest_pings()
    fresh = {t: rtt for t, (ts, rtt) in pings.items() if now - ts <= LIVE_FRESH_S}  # stale = unknown

    inet = [rtt for t, rtt in fresh.items() if t.startswith(INET_PREFIX)]
    answered = [r for r in inet if r is not None]
    cur = usage_now(conn, now)
    top = None
    if cur and cur["by_mac"]:
        mac, (d, u) = max(cur["by_mac"].items(), key=lambda kv: kv[1][0] + kv[1][1])
        if d + u >= 0.5:
            top = {"name": _live_namer(conn)(mac), "down_mbps": round(d, 1), "up_mbps": round(u, 1)}
    hs = live.host_sample(max_age_s=LIVE_FRESH_S, now=now)
    router_ms = fresh.get(TARGET_GATEWAY)
    return {"ts": now,
            "internet_ms": round(min(answered), 1) if answered else None,
            # down only when recent pings were sent and none came back; no recent pings at all
            # (a stalled pinger) is unknown, not down
            "internet_up": bool(answered) if inet else None,
            "router_ms": round(router_ms, 1) if router_ms is not None else None,
            "down_mbps": cur["down_mbps"] if cur else None, "up_mbps": cur["up_mbps"] if cur else None,
            "traffic_ts": cur["ts"] if cur else None, "busiest": top,
            "cpu_pct": hs.get("cpu_pct") if hs else None,
            "mem_used_pct": round(100 * (1 - hs["mem_avail"] / hs["mem_total"]), 1) if hs and hs.get("mem_total") else None}


def long_range(minutes):
    """Does a range reach past the detail tables' retention? Then it's drawn wholly from their
    hourly summaries (ending at the last whole hour), never from a mix of the two."""
    return minutes * 60 > store.DETAIL_DAYS * 86400


def host_view(conn, minutes):
    """The computer running Hearth: latest reading, plain-language warnings, a chart series,
    and its biggest programs with how much they changed over the window."""
    now = time.time()
    last = conn.execute("""SELECT ts, cpu, mem_avail, mem_total, commit_bytes, commit_limit, pool_paged,
                                  pool_nonpaged, handles, uptime_s FROM host_stats ORDER BY ts DESC LIMIT 1""").fetchone()
    if not last or now - last[0] > 600:
        return {"available": False}
    keys = ["ts", "cpu_pct", "mem_avail", "mem_total", "commit", "commit_limit", "pool_paged", "pool_nonpaged",
            "handles", "uptime_s"]
    cur = dict(zip(keys, last))
    since = now - minutes * 60
    pts = conn.execute("SELECT MAX(ts) FROM host_procs").fetchone()[0]
    procs = [(n, b, c, h, mx if mx is not None else h) for n, b, c, h, mx in conn.execute(
        "SELECT name, private, count, handles, max_handles FROM host_procs WHERE ts = ?", (pts,))] if pts else []
    # each program's change over the window; leaks are judged by the collector every 5 minutes
    first_ts = conn.execute("SELECT MIN(ts) FROM host_procs WHERE ts >= ?", (since,)).fetchone()[0]
    before = dict(conn.execute("SELECT name, private FROM host_procs WHERE ts = ?", (first_ts,))) if first_ts else {}
    leaking = [tuple(x) for x in store.get_state(conn, host.LEAKS_STATE_KEY, []) or []]
    pool = host_pool(conn, cur.get("pool_nonpaged"))
    hourly = long_range(minutes)
    bucket = max(60, int(minutes * 60 / 240) // 60 * 60)
    if hourly:
        bucket = max(3600, bucket // 3600 * 3600)
        q = """SELECT CAST(ts / ? AS INTEGER) * ?, AVG(cpu_avg), MAX(commit_max), MAX(commit_limit_max),
                     MIN(mem_avail_min), MAX(mem_total_max) FROM host_stats_1h WHERE ts >= ? GROUP BY 1 ORDER BY 1"""
    else:
        q = """SELECT CAST(ts / ? AS INTEGER) * ?, AVG(cpu), MAX(commit_bytes), MAX(commit_limit),
                     MIN(mem_avail), MAX(mem_total) FROM host_stats WHERE ts >= ? GROUP BY 1 ORDER BY 1"""
    series = [[b, round(cpu, 1), round(100 * cm / cl, 1) if cl else None, round(100 * (mt - ma) / mt, 1) if mt else None]
              for b, cpu, cm, cl, ma, mt in conn.execute(q, (bucket, bucket, since)) if cpu is not None]
    return {"available": True, "now": now, "minutes": minutes, "current": cur,
            "warnings": [{"level": lvl, "text": t} for lvl, t in host.warnings(cur, leaking, procs, pool)],
            "processes": [{"name": n, "private": b, "count": c, "handles": h, "max_handles": mx,
                           "change": (b - before[n]) if n in before else None,
                           # levels for the two cells the page colours (thresholds stay here)
                           "change_level": lv.WARN if n in before and b - before[n] > host.LEAK_MIN_GROWTH else None,
                           "handles_level": lv.BAD if (mx or 0) >= host.PROCESS_HANDLES_WARN else None}
                          for n, b, c, h, mx in sorted(procs, key=lambda r: -r[1])],
            "series": {"bucket_s": bucket, "points": series}}


def busiest_during(rows, start, end, name, top=2, min_mbps=1.0, max_dur=None):
    """Who was using the internet during [start, end]: the readings whose span overlaps it.
    rows: [(ts, mac, dur, rx, tx)] sorted by ts. Only readings ending in [start, end + max_dur]
    can overlap, so the scan jumps straight there; readings spanning a long gap (longer than
    max_dur, e.g. after the router couldn't be read) are skipped - their average says nothing
    about one moment. Returns a sentence, or None if nobody was busy."""
    max_dur = max_dur or 3 * router.poll_interval_s()
    lo = bisect.bisect_left(rows, (start,))
    hi = bisect.bisect_right(rows, (end + max_dur, chr(0x10FFFF)))
    rate = {}
    for ts, mac, dur, rx, tx in rows[lo:hi]:
        if 0 < dur <= max_dur and ts - dur <= end:
            d, u = rx * 8 / dur / MB, tx * 8 / dur / MB
            if d + u > sum(rate.get(mac, (0, 0))):
                rate[mac] = (d, u)
    busy = sorted(((m, d, u) for m, (d, u) in rate.items() if d + u >= min_mbps), key=lambda x: -(x[1] + x[2]))
    if not busy:
        return None
    return "Using the internet then: " + ", ".join(
        f"{name(m)} {d:.1f} Mb/s down, {u:.1f} up" for m, d, u in busy[:top])


def _answered(rtts):
    return [r for r in rtts if r is not None]


def status(conn):
    """Compact current health, for Home Assistant or scripts."""
    now = time.time()
    by = fetch_raw(conn, now - 300)
    inet = [r for t, s in by.items() if t.startswith(INET_PREFIX) for ts, r in s if ts >= now - 60]
    recent = [r for t, s in by.items() if t.startswith(INET_PREFIX) for ts, r in s if ts >= now - 15]
    gw = [r for ts, r in by.get(TARGET_GATEWAY, []) if ts >= now - 60]
    inet_5m = [r for t, s in by.items() if t.startswith(INET_PREFIX) for _, r in s]
    labels, devnames = store.labels(conn), device_names(conn)
    meshidx = mesh_index(conn)
    snap = store.topology_at(store.topology_history(conn, now), now)
    inc = cached(incidents, conn, 60)
    cur = usage_now(conn, now)
    today = usage_totals(conn, _local_midnight(now), now)
    has_router = conn.execute("SELECT 1 FROM router_clients LIMIT 1").fetchone() is not None
    hv = cached(host_view, conn, 60)
    rt, rt_fresh = router_latest(conn, now)
    return {
        # the router's own health (None when Hearth can't read it)
        "router_temp_c": rt["temp_c"] if rt_fresh else None,
        "router_uptime_s": rt["uptime_s"] if rt_fresh else None,
        # the computer running Hearth (None when not measured)
        "host_cpu_pct": hv["current"]["cpu_pct"] if hv.get("available") else None,
        "host_commit_pct": round(100 * hv["current"]["commit"] / hv["current"]["commit_limit"], 1)
        if hv.get("available") and hv["current"]["commit_limit"] else None,
        "host_warnings": len([w for w in hv.get("warnings", []) if w["level"] != "info"]) if hv.get("available") else None,
        "host_top_warning": next((w["text"] for w in hv.get("warnings", []) if w["level"] != "info"), None),
        # internet traffic through the router (None when Hearth can't read the router)
        "down_mbps": cur["down_mbps"] if cur else None,
        "up_mbps": cur["up_mbps"] if cur else None,
        "today_down_gb": round(today[0] / 1e9, 2) if has_router else None,
        "today_up_gb": round(today[1] / 1e9, 2) if has_router else None,
        "internet_up": bool(_answered(recent)),
        "internet_measured": bool(recent),  # any internet ping in the last 15 s (else unknown, not down)
        "internet_ms": pct(_answered(inet), .5), "internet_p95_ms": pct(_answered(inet), .95),
        "router_ms": pct(_answered(gw), .5),
        "loss_pct_5m": round(100 * (len(inet_5m) - len(_answered(inet_5m))) / len(inet_5m), 2) if inet_5m else None,
        "path": path_label(snap, labels, devnames, meshidx),
        # for the first-run welcome (#105): when this Hearth started, and whether it has worked out
        # the network's layout yet
        "started": round(HEARTH_STARTED), "layout_known": snap is not None,
        "incidents_1h": inc["total"],
        "last_incident": inc["incidents"][0]["verdict"] if inc["incidents"] else None,
        # episodes (outages, problems, slow spells) and momentary spikes; incidents_1h above is
        # deprecated and goes in step 3 of the redesign
        "episodes_1h": inc["episode_total"],
        # the dashboard's header reads these on every tab (one cached request, not the incidents list)
        "episodes_level_1h": inc["episode_level"], "episodes_breakdown_1h": inc["episode_breakdown"],
        # a mesh change waiting for your confirmation: the dashboard shows a banner on every tab
        "mesh_pending": mesh.pending_cert(conn) is not None,
        "spikes_1h": inc["spikes_total"],
        "spikes_usual_per_hour": inc["spikes_usual_per_hour"],
        "last_episode": inc["episodes"][0]["cause"] if inc["episodes"] else None,
        # what feeds Hearth, and whether each works (sources.py); history = slowdowns and outages
        # being saved for long ranges. sources_failing: how many set-up sources are failing
        **sources_view(conn, now),
        # alerts (alerts.py): how many are active, the newest thing to tell you, how many unseen
        **alerts.status_fields(conn, now),
        # the weekly digest's one-line headline (digest.py), for Home Assistant to send on
        "digest_headline": (digest.latest(conn) or {}).get("headline"),
        "updated": round(now),
    }


def sources_view(conn, now):
    all_ = {**sources.states(conn), "history": _history_source(conn, now)}
    return {"sources": all_, "sources_failing": sources.failing(all_)}


HISTORY_STARTING_S = 600   # just started: saved history isn't counted as failing before its first run


def _history_source(conn, now):
    complete, error = history_state(conn, now)
    st = store.get_state(conn, EPISODES_STORE_KEY) or {}
    st = st if isinstance(st, dict) else {}
    # in the first minutes after a start, before the first store run, history isn't failing: it
    # hasn't had its turn yet (ok None, not yet known), so a fresh install shows nothing failing
    starting = not complete and not st.get("last_error") and now - HEARTH_STARTED < HISTORY_STARTING_S
    return {"configured": True, "ok": None if starting else complete, "since": st.get("since"),
            "error": None if starting else error}


def _safe_verdict(conn):
    """The shared verdict, or {text: None, level: None} if it can't be worked out - it mustn't
    take /api/status or /api/kpi down with it."""
    try:
        return cached(verdict_view, conn, 60)
    except Exception as e:  # noqa: BLE001
        log(f"verdict unavailable ({e!r})")
        return {"text": None, "level": None}


def status_view(conn, _minutes):
    """status() in the cached(fn, conn, minutes) shape, with the verdict (shared with /api/kpi)."""
    v = _safe_verdict(conn)
    return {**status(conn), "verdict": v["text"], "verdict_level": v["level"]}


# --------------------------------------------------------------------------- headline figures
ROUTER_STATS_MAX_AGE_S = 600   # an older health reading isn't shown as the router's state now


def router_temp_limits():
    """(warn, bad) in °C from the config. A value that isn't a finite number, or a pair where
    warn isn't below bad, falls back to both defaults - colours must always mean something."""
    try:
        warn, bad = float(CFG.get("router_temp_warn_c")), float(CFG.get("router_temp_bad_c"))
        if math.isfinite(warn) and math.isfinite(bad) and warn < bad:
            return warn, bad
    except (TypeError, ValueError):
        pass
    return float(DEFAULTS["router_temp_warn_c"]), float(DEFAULTS["router_temp_bad_c"])


def router_latest(conn, now):
    """The router's latest health reading, and whether it's recent enough to show as now.
    One indexed lookup: cheap enough for status()."""
    last = conn.execute("SELECT ts, temp_c, uptime_s, load1, mem_used_pct FROM router_stats "
                        "ORDER BY ts DESC LIMIT 1").fetchone()
    if not last:
        return None, False
    return dict(zip(("ts", "temp_c", "uptime_s", "load1", "mem_used_pct"), last)), now - last[0] <= ROUTER_STATS_MAX_AGE_S


def host_pool(conn, total):
    """Who holds the non-paged pool, from the host collector's hourly readings (#127): the
    growing tags, the biggest now, and the drivers they belong to (host.pool_cause reads it)."""
    hist = store.get_state(conn, host.POOL_HISTORY_KEY) or {}
    latest = sorted(((pts[-1][1], t) for t, pts in hist.items() if isinstance(pts, list) and pts), reverse=True)
    leaks = [tuple(x) for x in store.get_state(conn, host.POOL_LEAKS_KEY) or [] if isinstance(x, list) and len(x) == 4]
    cached = store.get_state(conn, host.POOL_OWNERS_KEY)
    owners = cached.get("owners") if isinstance(cached, dict) and isinstance(cached.get("owners"), dict) else {}
    return {"leaks": leaks, "top": [(t, size) for size, t in latest[:5]], "owners": owners, "total": total}


def router_health(conn, now):
    """The router's latest health reading, how its temperature rates, and the last day of
    temperatures (10-minute peaks) for a small chart."""
    warn, bad = router_temp_limits()
    cur, fresh = router_latest(conn, now)
    if not cur:
        return {"available": False, "level": lv.UNKNOWN, "why": "no reading", "warn_c": warn, "bad_c": bad, "series": []}
    series = [[b, round(t, 1)] for b, t in conn.execute(
        """SELECT CAST(ts / 600 AS INTEGER) * 600, MAX(temp_c) FROM router_stats
           WHERE ts >= ? AND temp_c IS NOT NULL GROUP BY 1 ORDER BY 1""", (now - 86400,))]
    res = lv.temp_level(cur["temp_c"], warn, bad) if fresh else lv.result(lv.UNKNOWN, "no recent reading")
    return {**cur, "available": fresh, "level": res["level"], "why": res["why"],
            "warn_c": warn, "bad_c": bad, "series": series, "link": router.link_now(conn, now)}


def internet_kpi(st):
    """How the internet connection is doing right now, from status(): lost pings over 5 minutes,
    and how far the slowest 5% of pings sit above the typical one - the same limits used to
    judge WiFi devices. Lag spikes show up here even when the typical ping looks fine."""
    p50, p95 = st["internet_ms"], st["internet_p95_ms"]
    res = lv.internet_level(st)
    measured = st.get("internet_measured", True)
    # up: True / False (pings sent, none answered) / None (no pings in 15 s - not measured, never "down")
    return {"up": st["internet_up"] if measured else None, "measured": measured,
            "loss_pct": st["loss_pct_5m"], "p50_ms": p50, "p95_ms": p95,
            "incidents_1h": st["incidents_1h"], "level": res["level"], "why": res["why"],
            "episodes_1h": st.get("episodes_1h"), "spikes_1h": st.get("spikes_1h"),
            "spikes_usual_per_hour": st.get("spikes_usual_per_hour")}


def mesh_kpi(mv):
    """The mesh satellite with the weakest link, by the nodes' own levels (so the tile and the
    map agree). Among equal levels an offline unit comes first, then the lower best-band signal
    (a unit with no reading counts as 0 dBm there, i.e. after the measured ones)."""
    if not mv.get("available"):
        return {"available": False}
    sats = [n for n in mv.get("nodes", []) if n.get("role") != "main"]
    if not sats:
        return {"available": True, "satellites": 0, "level": lv.UNKNOWN, "why": "no satellites"}

    def best(n):
        rssi = n.get("rssi") or {}
        return max(rssi.items(), key=lambda kv: kv[1]) if rssi else (None, None)

    # worst level first; among equals an offline unit beats a weak one, then the lower signal
    worst = max(sats, key=lambda n: (lv.rank(n.get("level")), not n.get("online"),
                                     -(best(n)[1] if best(n)[1] is not None else 0)))
    band, dbm = best(worst)
    why = worst.get("why") or ""
    unmeasured = [n.get("name") or n["mac"] for n in sats if n is not worst and n.get("level") == lv.UNKNOWN]
    if unmeasured:
        why += f"; {', '.join(unmeasured)} not measured"
    return {"available": True, "satellites": len(sats), "name": worst.get("name") or worst.get("mac"),
            "backhaul": "offline" if not worst.get("online") else worst.get("backhaul"),
            "band": band, "rssi": dbm, "rate_rx": (worst.get("rate_rx") or {}).get(band) if band else None,
            "level": worst.get("level") or lv.UNKNOWN, "why": why}


def wifi_kpi(mv):
    """Devices on the mesh's WiFi, and which of them are connected poorly (judged from Hearth's
    pings, see mesh.device_quality). Phones dozing to save power aren't counted as poor."""
    if not mv.get("available"):
        return {"available": False}
    wireless = [d for d in mv.get("devices", []) if (d.get("link") or "").startswith("band")]
    poor = [{"name": d.get("name") or d.get("mac"), "why": d.get("quality_why")} for d in wireless if d.get("quality") == "poor"]
    return {"available": True, "total": len(wireless), "poor": poor,
            "fair": sum(d.get("quality") == "fair" for d in wireless),
            **_wifi_level(wireless, poor)}


def _wifi_level(wireless, poor):
    """warn if any device is poorly connected; ok only if at least one was actually judged;
    unknown when there are no wireless devices or none was measured."""
    if poor:
        return lv.result(lv.WARN, f"{len(poor)} poorly connected")
    if not wireless:
        return lv.result(lv.UNKNOWN, "no wireless devices")
    if not any(d.get("level") in (lv.OK, lv.WARN, lv.BAD) for d in wireless):
        return lv.result(lv.UNKNOWN, "not measured yet")
    return lv.result(lv.OK, "all connected well")


def verdict_from(internet, episodes_bad, router, mesh_tile, wifi):
    """The one-sentence answer to "is it OK?": the internet first, then at most two other
    issues, worst first. Its level is the worst of everything mentioned."""
    lvl = internet.get("level")
    if lvl == lv.UNKNOWN and all(x.get("level") in (None, lv.UNKNOWN) for x in (router, mesh_tile, wifi)):
        return {"level": lv.UNKNOWN, "text": "Hearth is still measuring."}  # nothing known yet
    if internet.get("up") is False and lvl == lv.BAD:   # never claim an outage nobody measured
        first = "Your internet is down"
    else:
        first = {lv.OK: "Your internet is fine", lv.WARN: "Your internet is slow at times",
                 lv.BAD: "Your internet is having problems"}.get(lvl, "Your internet hasn't been measured yet")
    if episodes_bad:
        what = "1 outage or problem" if episodes_bad == 1 else f"{episodes_bad} outages or problems"
        if lvl == lv.UNKNOWN:  # Hearth stopped measuring recently, after trouble earlier in the hour
            first = f"Your internet hasn't been measured in the last few minutes; {what} earlier in the hour"
        elif lvl == lv.OK:     # it's over: say so, so an amber verdict doesn't read as "fine"
            first = f"Your internet is fine now; {what} in the last hour"
        else:
            first += f"; {what} in the last hour"
    issues = []  # (rank, text, level)
    if mesh_tile.get("level") in (lv.WARN, lv.BAD):
        what = "is off the mesh" if mesh_tile.get("backhaul") == "offline" else "has a weak link to the mesh"
        issues.append((lv.rank(mesh_tile["level"]), f"{mesh_tile.get('name') or 'A mesh unit'} {what}", mesh_tile["level"]))
    if router.get("level") in (lv.WARN, lv.BAD):
        temp = router.get("temp_c")
        text = f"The router is hot ({temp:g} °C)" if isinstance(temp, (int, float)) else \
            f"The router needs a look ({router.get('why') or 'its health reading is off'})"
        issues.append((lv.rank(router["level"]), text, router["level"]))
    poor = len(wifi.get("poor") or [])
    if poor:
        issues.append((lv.rank(lv.WARN), f"{poor} device{' has' if poor == 1 else 's have'} weak WiFi", lv.WARN))
    issues.sort(key=lambda x: -x[0])
    shown = issues[:2]
    # the level is about now: trouble earlier in the hour (episodes already over) is amber, not
    # red; a problem now is judged by the internet's own level
    level = lv.worst([lvl or lv.UNKNOWN] + ([lv.WARN] if episodes_bad else []) + [x[2] for x in shown])
    text = first + "." + "".join(f" {t}." for _, t, _ in shown)
    return {"level": level, "text": text}


def verdict_view(conn, _minutes):  # _minutes: only the cache key (callers pass 60); the verdict is about now
    """The verdict in the cached(fn, conn, minutes) shape. Through cached() with a 60-minute key
    it's kept 2 s (cached()'s TTL for windows up to an hour) and shared, so /api/kpi and
    /api/status give the same sentence, "your internet is down" is at most 2 s old, and Home
    Assistant polling doesn't recompute it."""
    now = time.time()
    st = status(conn)
    mv = cached(mesh_view, conn, 60)
    inc = cached(incidents, conn, 60)
    bad = sum(1 for e in inc["episodes"] if e["level"] == ep.LEVEL_BAD)
    return verdict_from(internet_kpi(st), bad, router_health(conn, now), mesh_kpi(mv), wifi_kpi(mv))


def kpi_view(conn, _minutes):
    """The dashboard's second row of headline figures. Thresholds live here, not in the page."""
    now = time.time()
    st = status(conn)
    mv = cached(mesh_view, conn, 60)
    today = ({"down_gb": st["today_down_gb"], "up_gb": st["today_up_gb"]}
             if st["today_down_gb"] is not None else None)
    return {"now": now, "router": router_health(conn, now), "internet": internet_kpi(st), "today": today,
            "mesh": mesh_kpi(mv), "wifi": wifi_kpi(mv), "verdict": _safe_verdict(conn),
            "calls": calls.calls_kpi(conn, now)}


# Analysis is recomputed from raw rows, so cache it briefly: a dashboard left open on a long
# window would otherwise redo seconds of work every refresh. Size-capped (oldest evicted) so
# no sequence of requests can grow it without limit.
_CACHE_MAX = 64
_cache, _cache_lock = OrderedDict(), threading.Lock()
_compute_locks = {}  # one per key: concurrent misses compute once ("single flight")


def cached(fn, conn, minutes, ttl=None):
    ttl = ttl or (2 if minutes <= 60 else 15 if minutes <= 360 else 60)
    key = (fn.__name__, minutes, ttl)  # ttl too: one view asked for at two freshnesses is two entries

    def fresh():
        hit = _cache.get(key)
        return hit[1] if hit and time.time() - hit[0] < ttl else None

    with _cache_lock:
        val = fresh()
        if val is not None:
            return val
        lock = _compute_locks.setdefault(key, threading.Lock())
    with lock:
        with _cache_lock:
            val = fresh()  # another request may have filled it while we waited
            if val is not None:
                return val
        val = fn(conn, minutes)
        with _cache_lock:
            _cache[key] = (time.time(), val)
            _cache.move_to_end(key)
            while len(_cache) > _CACHE_MAX:
                old, _ = _cache.popitem(last=False)
                _compute_locks.pop(old, None)
    return val


def clear_cache():
    with _cache_lock:
        _cache.clear()
    with _mesh_lock:
        _mesh_cache.update(ts=0.0, val=None)
    _namer_cache.update(ts=0.0, fn=None)  # a rename shows up in the live strip straight away
