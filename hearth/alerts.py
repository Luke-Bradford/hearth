"""Step 4, part 4a (#88): alerts - what needs you, remembered, so each problem is said once.

Every ALERT_INTERVAL_S the conditions are checked (alerts_loop in collectors.py):
- "state" alerts last while their condition holds: raised once, kept up to date, and cleared
  only after it's been gone for CLEAR_AFTER checks in a row, so a flapping problem doesn't make
  a stream of alerts;
- "event" alerts are things that happened (an outage that ended): raised once, already over.

Each condition can be turned off in Settings (settings.py: alert_*). Alerts are shown in the page
and summarised in /api/status (alerts_active, alert_latest) for Home Assistant; delivery channels
come later (#37)."""
import re
import time

from . import calls, levels as lv, naming, overview, reports, settings
from .config import device_target

CLEAR_AFTER = 2                 # checks in a row a state alert's condition must be gone
KEEP_DAYS = 90
RECENT_DAYS = 7                 # cleared alerts listed in the page
RECENT_MAX = 100
OUTAGE_LOOKBACK_S = 3600        # outages that ended this recently are announced (once)
SIDE_WORDS = {"isp": "your ISP or beyond", "home": "your home network", "unclear": "unclear where"}


def _stable(text):
    """A key part from a sentence whose numbers change ("3.5 GB" -> "#"), so the same problem
    with a new figure is the same alert."""
    return re.sub(r"\d+(?:[.,:]\d+)*", "#", text)[:120]


def conditions(conn, now):
    """[{key, level, text, tab, item, kind}] that hold now, for the conditions turned on."""
    out = []
    if settings.value("alert_attention"):
        for it in overview.attention(conn, now):
            if it["level"] in (lv.WARN, lv.BAD):
                # item and sentence: the router's health and its restart share the item "router"
                # but are two problems (#97)
                out.append({"key": f"attention|{it.get('item') or ''}|{_stable(it['text'])}", "level": it["level"],
                            "text": it["text"], "tab": it.get("tab"), "item": it.get("item"), "kind": "state"})
    if settings.value("alert_calls"):
        c = calls.calls_kpi(conn, now)
        if c["level"] == lv.BAD:
            out.append({"key": "calls|poor", "level": lv.BAD, "text": f"Calls would sound poor now: {c['why']}",
                        "tab": "overview", "item": None, "kind": "state"})
    if settings.value("alert_new_devices"):
        out += new_devices(conn, now)
    if settings.value("alert_outages"):
        for e in reports._stored(conn, reports.OUTAGE_KINDS, now - OUTAGE_LOOKBACK_S, now):
            if e["end"] < now - OUTAGE_LOOKBACK_S:
                continue
            mins = max(1, round((e["end"] - e["start"]) / 60))
            out.append({"key": f"outage|{int(e['start'])}", "level": lv.BAD,
                        "text": f"The internet was down {mins} min ({SIDE_WORDS[reports.SIDE[e['kind']]]})",
                        "tab": "history", "item": f"ep:{int(e['start'])}", "kind": "event"})
    return out


def private_mac(mac):
    """A locally administered address (the second-lowest bit of the first byte): what phones and
    laptops use when they hide their real MAC, a different one per network or over time."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, AttributeError, IndexError):
        return False


def new_devices(conn, now):
    """Event alerts for MACs Hearth has never seen, recording them. The first time (nothing
    recorded yet) everything already on the network is recorded quietly: turning this on doesn't
    announce the whole house. A private (rotating) address says so, rather than claiming a
    stranger joined."""
    macs = {}
    for mac, ip in conn.execute("SELECT mac, ip FROM devices WHERE mac IS NOT NULL AND mac != ''"):
        m = naming.normalise_mac(mac)
        if m:
            macs.setdefault(m, ip)
    known = {m for (m,) in conn.execute("SELECT mac FROM device_macs")}
    fresh = [(m, ip) for m, ip in macs.items() if m not in known]
    conn.executemany("INSERT OR IGNORE INTO device_macs VALUES (?, ?, ?)",
                     [(m, now, int(private_mac(m))) for m, _ in fresh])
    if not known:
        return []
    names = naming.device_names(conn)
    out = []
    for m, ip in fresh:
        did = device_target(m, ip)
        name = names.get(did) or ip
        text = (f"A phone or laptop using a private address joined: {name}" if private_mac(m)
                else f"New device on your network: {name}")
        out.append({"key": f"newdev|{m}", "level": lv.WARN, "text": text, "tab": "devices", "item": did, "kind": "event"})
    return out


def run(conn, now=None):
    """One check: raise what's new, refresh what continues, clear what's been gone long enough."""
    now = now or time.time()
    found = {}
    for f in conditions(conn, now):   # one per key: two conditions agreeing are one alert, the worst of them
        if f["key"] not in found or lv.rank(f["level"]) > lv.rank(found[f["key"]]["level"]):
            found[f["key"]] = f
    found = list(found.values())
    active = {r[1]: r for r in conn.execute(
        "SELECT id, key, missing FROM alerts WHERE cleared IS NULL AND kind = 'state'")}
    seen_keys = set()
    for f in found:
        seen_keys.add(f["key"])
        if f["kind"] == "event":
            if not conn.execute("SELECT 1 FROM alerts WHERE key = ?", (f["key"],)).fetchone():
                conn.execute("INSERT INTO alerts (key, level, text, tab, item, first, last, cleared, kind) "
                             "VALUES (?,?,?,?,?,?,?,?, 'event')", (f["key"], f["level"], f["text"], f["tab"], f["item"],
                                                                  now, now, now))
        elif f["key"] in active:
            conn.execute("UPDATE alerts SET level = ?, text = ?, tab = ?, item = ?, last = ?, missing = 0 WHERE id = ?",
                         (f["level"], f["text"], f["tab"], f["item"], now, active[f["key"]][0]))
        else:
            conn.execute("INSERT INTO alerts (key, level, text, tab, item, first, last, kind) VALUES (?,?,?,?,?,?,?, 'state')",
                         (f["key"], f["level"], f["text"], f["tab"], f["item"], now, now))
    for key, (aid, _key, missing) in active.items():
        if key not in seen_keys:
            if missing + 1 >= CLEAR_AFTER:
                conn.execute("UPDATE alerts SET cleared = ?, missing = ? WHERE id = ?", (now, missing + 1, aid))
            else:
                conn.execute("UPDATE alerts SET missing = ? WHERE id = ?", (missing + 1, aid))
    conn.execute("DELETE FROM alerts WHERE cleared IS NOT NULL AND cleared < ?", (now - KEEP_DAYS * 86400,))


_COLS = ("id", "key", "level", "text", "tab", "item", "first", "last", "cleared", "seen", "kind")


def view(conn, now=None):
    """/api/alerts: active alerts (worst first, then newest), what cleared or happened in the last
    RECENT_DAYS (newest first), and how many of all those you haven't seen."""
    now = now or time.time()
    cols = ", ".join(_COLS)
    # active ones on their own query: never cut off by the recent list's limit, however old they are
    active = sorted((dict(zip(_COLS, r)) for r in conn.execute(f"SELECT {cols} FROM alerts WHERE cleared IS NULL")),
                    key=lambda r: (-lv.rank(r["level"]), -r["first"]))
    recent = [dict(zip(_COLS, r)) for r in conn.execute(
        f"SELECT {cols} FROM alerts WHERE cleared >= ? ORDER BY cleared DESC LIMIT ?", (now - RECENT_DAYS * 86400, RECENT_MAX))]
    (unseen,) = conn.execute("SELECT COUNT(*) FROM alerts WHERE seen = 0 AND (cleared IS NULL OR cleared >= ?)",
                             (now - RECENT_DAYS * 86400,)).fetchone()
    return {"active": active, "recent": recent, "unseen": unseen}


def mark_seen(conn):
    conn.execute("UPDATE alerts SET seen = 1 WHERE seen = 0")


def status_fields(conn, now=None):
    """For /api/status (Home Assistant): how many alerts are active, and the newest thing to tell
    you - the newest active alert, or an event from the last hour."""
    now = now or time.time()
    (n,) = conn.execute("SELECT COUNT(*) FROM alerts WHERE cleared IS NULL").fetchone()
    row = conn.execute("SELECT text FROM alerts WHERE cleared IS NULL OR (kind = 'event' AND first >= ?) "
                       "ORDER BY first DESC LIMIT 1", (now - 3600,)).fetchone()
    (unseen,) = conn.execute("SELECT COUNT(*) FROM alerts WHERE seen = 0 AND (cleared IS NULL OR cleared >= ?)",
                             (now - RECENT_DAYS * 86400,)).fetchone()
    return {"alerts_active": n, "alert_latest": row[0] if row else None, "alerts_unseen": unseen}
