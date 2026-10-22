"""The Overview tab's answer to "is everything all right?": the last 24 hours at a glance, and
what needs attention now. Both are gathered from levels and texts Hearth already works out
(the verdict, the mesh and Wi-Fi tiles, the router's health, this computer's warnings, the data
sources); nothing here adds a new judgement, and the page draws them as given."""
import time

from . import analysis, dns_health, levels as lv, mesh, security
from .config import CFG, inet_target

SLOT_S = 15 * 60          # the timeline's slots
SLOTS = 96                # 24 hours of them
ATTENTION_MAX = 8         # the list stays a glance, not a log
SOURCE_LABELS = {"router": "The router reading", "mesh": "The mesh reading", "upnp": "The router's UPnP reading",
                 "dns": "The DNS check",
                 "history": "Saving slowdowns and outages"}


def timeline(conn, now):
    """96 fifteen-minute slots ending with the current one, oldest first, each
    {start, level, measured, episodes}: level is the worst episode level touching the slot ("ok"
    when it was measured with none, "unknown" when it wasn't measured); measured = at least one
    per-minute row for an internet target in the slot (the current minute, not yet rolled up,
    counts from raw pings); episodes = the starts of the episodes it touches."""
    end = (int(now) // SLOT_S + 1) * SLOT_S
    start = end - SLOTS * SLOT_S
    inet = [inet_target(ip) for ip in CFG["internet_targets"]]
    marks = ",".join("?" * len(inet))
    measured = set()
    if inet:
        measured = {int(t) // SLOT_S * SLOT_S for (t,) in conn.execute(
            f"SELECT DISTINCT ts FROM pings_1m WHERE ts >= ? AND ts < ? AND target IN ({marks})", (start, end, *inet))}
        if conn.execute(f"SELECT 1 FROM pings WHERE ts >= ? AND target IN ({marks}) LIMIT 1",
                        (now - 120, *inet)).fetchone():
            measured.add(int(now) // SLOT_S * SLOT_S)
    episodes = analysis.cached(analysis.incidents, conn, 1440)["episodes"]
    slots = []
    for i in range(SLOTS):
        s = start + i * SLOT_S
        hit = [e for e in episodes if e["start"] < s + SLOT_S and e["end"] >= s]
        level = lv.worst([e["level"] for e in hit]) if hit else (lv.OK if s in measured else lv.UNKNOWN)
        slots.append({"start": s, "level": level, "measured": s in measured,
                      "episodes": sorted(e["start"] for e in hit)})
    return slots


def _security(conn, now):
    """The Security panel's warnings and problems (#131): a DMZ, admin open to the internet..."""
    return [_item(i["level"], i["text"], "system") for i in security.attention(conn, now)]


def _item(level, text, tab, item=None):
    return {"level": level, "text": text, "tab": tab, "item": item}


def _sources(conn, now):
    out = []
    for name, s in analysis.sources_view(conn, now)["sources"].items():
        if name == "dns" and s.get("error") == dns_health.NO_ANSWER:
            continue   # nothing answering is a DNS problem, said by _dns, not a broken check
        if s.get("configured") and s.get("ok") is False:
            level = lv.WARN if name == "history" else lv.BAD
            why = f": {s['error']}" if s.get("error") else ""
            out.append(_item(level, f"{SOURCE_LABELS.get(name, name)} isn't working{why}", "system", f"src:{name}"))
    return out


def _pending(conn):
    """A mesh change waiting for confirmation: gathered on its own, so it shows even when the
    mesh view below can't be worked out - it's the one thing you can act on."""
    pending = mesh.pending_cert(conn)
    if not pending:
        return []
    what = "login keys" if pending.get("kind") == "keys" else "security certificate"
    return [_item(lv.BAD, f"Your mesh's main unit has a new {what} to confirm - Hearth stopped reading the "
                          "mesh until you decide", "network")]


def _mesh(conn):
    out = []
    mv = analysis.cached(analysis.mesh_view, conn, 60)
    if not mv.get("available"):
        return out
    seen = set()
    for n in mv.get("nodes", []):
        if n.get("role") == "main":
            continue
        name, unit = n.get("name") or n["mac"], f"unit:{n['mac']}"
        if not n.get("online"):
            out.append(_item(lv.BAD, f"{name} is off the mesh", "network", unit))
            continue
        if n.get("level") in (lv.WARN, lv.BAD):
            why = f" ({n['why']})" if n.get("why") else ""
            out.append(_item(n["level"], f"{name} has a weak link to the mesh{why}", "network", unit))
        for f in n.get("findings") or []:
            if f.get("level") in (lv.WARN, lv.BAD) and f.get("text") not in seen:
                seen.add(f["text"])
                out.append(_item(f["level"], f["text"], "network", unit))
    poor = analysis.wifi_kpi(mv).get("poor") or []
    if poor:
        names = ", ".join(p["name"] for p in poor[:4]) + (f" and {len(poor) - 4} more" if len(poor) > 4 else "")
        out.append(_item(lv.WARN, f"{len(poor)} device{'s have' if len(poor) > 1 else ' has'} weak Wi-Fi: {names}",
                         "network"))
    return out


def _router(conn, now):
    out = []
    rh = analysis.router_health(conn, now)
    if rh.get("available") and rh.get("level") in (lv.WARN, lv.BAD):
        out.append(_item(rh["level"], f"The router needs a look: {rh.get('why') or 'its health reading is off'}",
                         "system", "router"))
    # any hour that overlaps the last day: the one that began just over 24 h ago counts too
    row = conn.execute("SELECT MAX(ts) FROM router_stats_1h WHERE restarted = 1 AND ts > ?",
                       (now - 86400 - 3600,)).fetchone()
    if row and row[0] is not None:
        out.append(_item(lv.WARN, f"The router restarted in the last day (between {time.strftime('%H:%M', time.localtime(row[0]))}"
                                  f" and {time.strftime('%H:%M', time.localtime(row[0] + 3600))})", "system", "router"))
    return out


def _host(conn):
    hv = analysis.cached(analysis.host_view, conn, 60)
    return [_item(w["level"], f"This computer: {w['text']}", "system")
            for w in hv.get("warnings", []) if w.get("level") in (lv.WARN, lv.BAD)] if hv.get("available") else []


def _dns(conn, now):
    return [_item(level, text, "system", "src:dns") for level, text in dns_health.attention(conn, now)]


def attention(conn, now):
    """What needs attention, worst first, at most ATTENTION_MAX, each {level, text, tab, item}:
    tab is where to look, item (or None) what to open there. Each input is gathered on its own:
    one that fails becomes a single "couldn't check" item and the rest still show, so the list
    never goes blank because of one broken part."""
    items = []
    for what, gather in (("the data sources", lambda: _sources(conn, now)),
                         ("the mesh confirmation", lambda: _pending(conn)), ("the mesh", lambda: _mesh(conn)),
                         ("the router", lambda: _router(conn, now)), ("DNS", lambda: _dns(conn, now)),
                         ("this computer", lambda: _host(conn)),
                         ("what can reach your home", lambda: _security(conn, now))):
        try:
            items += gather()
        except Exception as e:  # noqa: BLE001 - one broken input must not hide the others
            items.append(_item(lv.WARN, f"Hearth couldn't check {what} ({type(e).__name__})", "system"))
    items.sort(key=lambda it: -lv.rank(it["level"]))   # stable: within a level, the order above
    return items[:ATTENTION_MAX]


def timeline_view(conn, _minutes):   # the cached(fn, conn, minutes) shape; _minutes is only the key
    return timeline(conn, time.time())


def attention_view(conn, _minutes):
    return attention(conn, time.time())


TIMELINE_TTL_S = 30    # moves in 15-minute slots
ATTENTION_TTL_S = 5    # close to the verdict's 2 s, so the sentence and the list agree


def overview_view(conn):
    """/api/overview: the two parts, each cached on its own (shared by every client; one
    computation per miss). Each part fails on its own too: a timeline that can't be worked out
    comes back empty with timeline_error, and the attention list still shows (attention already
    handles its own inputs one by one)."""
    out = {"timeline": [], "timeline_error": None,
           "attention": analysis.cached(attention_view, conn, 1440, ttl=ATTENTION_TTL_S)}
    try:
        out["timeline"] = analysis.cached(timeline_view, conn, 1440, ttl=TIMELINE_TTL_S)
    except Exception as e:  # noqa: BLE001 - the attention list mustn't go down with it
        out["timeline_error"] = f"the last 24 hours couldn't be worked out ({type(e).__name__})"
    return out
