"""Step 5, part 1 (#105): the Setup checklist - what Hearth found and what's missing, each with
the one next step in plain words. It reads what Hearth already has (the data sources, the
devices, the layout, the settings); nothing new is collected or sent."""
import os
import tempfile
import threading
import time

from . import analysis, mesh, net, notify, router, settings, sources, store
from . import levels as lv
from .config import CFG, inet_target

GLINET_HINTS = ("gl technologies", "gl.inet", "gl-inet", "glinet")   # the router integration Hearth supports
TPLINK_HINTS = ("tp-link", "tp link", "tplink")                     # TP-Link Deco: the mesh integration


def _item(key, title, level, text, action=None, optional=False):
    return {"key": key, "title": title, "level": level, "text": text, "action": action, "optional": optional}


def _source_state(conn, name):
    st = sources.read(conn, name) or {}
    if st.get("configured") and st.get("ok"):
        return "working", st
    if st.get("configured") and st.get("ok") is False:
        return "failing", st
    if st.get("configured") is False:
        return "off", st
    return "starting", st


def _router_maker(conn):
    gw = analysis._gateway_ip(conn)
    row = conn.execute("SELECT mac FROM devices WHERE ip = ? AND mac IS NOT NULL", (gw,)).fetchone() if gw else None
    return (net.vendor(row[0]) or "").strip() if row else ""


def _tplink_seen(conn):
    for (mac,) in conn.execute("SELECT mac FROM devices WHERE mac IS NOT NULL AND mac != ''"):
        if any(h in (net.vendor(mac) or "").lower() for h in TPLINK_HINTS):
            return True
    return False


def has_password(key):
    """Whether the credentials file holds this key - never what it is."""
    return router.has_password(router.credentials_path(), key)


def checklist(conn, now=None):
    """/api/setup: the items, each {key, title, level, text, action, optional}, and where the
    credentials file is (so a person on another device knows what to edit)."""
    now = now or time.time()
    items = []

    inet = [inet_target(ip) for ip in CFG["internet_targets"]]
    marks = ",".join("?" * len(inet)) or "NULL"
    replied = conn.execute(f"SELECT 1 FROM pings WHERE ts >= ? AND target IN ({marks}) AND rtt IS NOT NULL LIMIT 1",
                           (now - 60, *inet)).fetchone() if inet else None
    items.append(_item("measuring", "Measuring your internet", lv.OK if replied else lv.BAD,
                       f"Pinging the internet every {float(CFG['core_interval_s']):g} s." if replied else
                       "Hearth isn't getting replies from the internet right now.",
                       None if replied else "Check this computer is online, and that a firewall isn't blocking ping."))

    (devices,) = conn.execute("SELECT COUNT(*) FROM devices WHERE online = 1").fetchone()
    learned = store.topology_at(store.topology_history(conn, now), now) is not None
    items.append(_item("network", "Your network", lv.OK if devices and learned else lv.UNKNOWN,
                       (f"{devices} devices online; the layout is {'learned' if learned else 'still being learned'}." if devices
                        else "No devices found yet."),
                       None if devices and learned else "Give it about 5 minutes after starting." if devices or not learned
                       else "Check this computer is on the same network as your devices (discovery_subnet in config.json)."))

    state, st = _source_state(conn, sources.ROUTER)
    maker = _router_maker(conn)
    glinet = any(h in maker.lower() for h in GLINET_HINTS)
    looks = f"Your router looks like a {maker}." if maker else "Hearth couldn't tell what make your router is."
    if state == "working":
        items.append(_item("router", "Router readings", lv.OK, "Reading who uses the internet, the router's health and today's totals."))
    elif state == "failing":
        items.append(_item("router", "Router readings", lv.BAD, f"Set up, but failing: {st.get('error') or 'no detail'}.",
                           "Check the router password is right."))
    elif glinet:
        items.append(_item("router", "Router readings", lv.UNKNOWN,
                           f"{looks} Hearth can read it: who uses the internet, its temperature and today's totals.",
                           "Add the router's admin password below (on this computer) or in the credentials file.",
                           optional=True))
    else:
        items.append(_item("router", "Router readings", lv.UNKNOWN,
                           f"{looks} Per-device usage needs a GL.iNet router; UPnP (below) still gives totals.",
                           optional=True))

    state, st = _source_state(conn, sources.MESH)
    if state == "working":
        items.append(_item("mesh", "Mesh layout", lv.OK, "Reading your mesh: which unit each device is on, and every link's signal."))
    elif state == "failing":
        items.append(_item("mesh", "Mesh layout", lv.BAD, f"Set up, but failing: {st.get('error') or 'no detail'}.",
                           "Check the Deco password, or confirm a changed unit on the Network tab."))
    elif _tplink_seen(conn):
        items.append(_item("mesh", "Mesh layout", lv.UNKNOWN,
                           "TP-Link devices are on your network. If they're Deco mesh units, Hearth can draw the real layout.",
                           "Add the password the Deco app uses below (on this computer) or in the credentials file.",
                           optional=True))
    else:
        items.append(_item("mesh", "Mesh layout", lv.UNKNOWN,
                           "No supported mesh found - the map is worked out from reply times.", optional=True))

    state, st = _source_state(conn, sources.UPNP)
    why = str((st.get("detail") or {}).get("why") or "not available from your router")
    items.append(_item("upnp", "Router totals (UPnP)", lv.OK if state == "working" else lv.UNKNOWN,
                       "Reading the router's own traffic counters." if state == "working" else
                       why[:1].upper() + why[1:].rstrip(".") + ".",
                       None if state == "working" else "Optional: turn on UPnP in your router's settings if you want totals.",
                       optional=state != "working"))

    state, st = _source_state(conn, sources.DNS)
    items.append(_item("dns", "DNS check", {"working": lv.OK, "failing": lv.BAD}.get(state, lv.UNKNOWN),
                       "Checking each minute that names are being looked up." if state == "working" else
                       "Turned off." if state == "off" else st.get("error") or "Starting.",
                       "See System, DNS." if state == "failing" else None))

    on = [k for k in ("alert_attention", "alert_outages", "alert_new_devices", "alert_calls") if settings.value(k)]
    items.append(_item("alerts", "Alerts", lv.OK if on else lv.UNKNOWN,
                       f"{len(on)} kind{'s' if len(on) != 1 else ''} of alert on." if on else "Every kind of alert is off.",
                       None if on else "Turn them on in Settings, below.", optional=not on))

    state, st = _source_state(conn, sources.NOTIFY)
    if state == "working":
        kinds = " and ".join((st.get("detail") or {}).get("channels") or []) or "your channel"
        items.append(_item("notify", "Notifications", lv.OK, f"Alerts are sent to {kinds}."))
    elif state == "failing":
        items.append(_item("notify", "Notifications", lv.BAD, f"Set up, but failing: {st.get('error') or 'no detail'}.",
                           "Check the address below, then press Send a test."))
    else:
        items.append(_item("notify", "Notifications", lv.UNKNOWN,
                           "Get alerts on your phone: Hearth can send them to ntfy (free, no account), Discord, "
                           "Slack or any webhook.",
                           "Add an address below (on this computer) or in the credentials file.", optional=True))

    items.append(_item("homeassistant", "Home Assistant", lv.UNKNOWN,
                       "Optional: show Hearth's status in Home Assistant and notify from its alerts.",
                       "Copy homeassistant/hearth_sensors.yaml into Home Assistant's configuration.", optional=True))

    return {"items": items, "credentials_file": router.credentials_path(),
            "credentials": {"router": has_password(router.PASSWORD_KEY), "mesh": has_password(mesh.PASSWORD_KEY),
                            # which kind each channel is - never its address - and whether a token is set
                            "notify": _channel_kinds(), "notify_token": has_password(notify.TOKEN_KEY)}}


def _channel_kinds():
    try:
        chans, _ = notify.channels()
    except Exception:   # noqa: BLE001 - only status: a file that can't be read shows nothing set
        return [None] * len(notify.URL_KEYS)
    by_key = {k: (kind or "unusable") for k, _, kind in chans}
    return [by_key.get(k) for k in notify.URL_KEYS]


# ---------------------------------------------------------------- passwords from the page (step 5.2)
CREDENTIAL_KEYS = {"router": router.PASSWORD_KEY, "mesh": mesh.PASSWORD_KEY,
                   "notify": notify.URL_KEYS[0], "notify_2": notify.URL_KEYS[1], "notify_token": notify.TOKEN_KEY}
REMOVABLE = ("notify", "notify_2", "notify_token")   # "" takes the line out: a channel can be removed
_write_lock = threading.Lock()   # read-modify-write of the file: two saves at once mustn't lose one
PASSWORD_MAX = 128


class Invalid(ValueError):
    """A password the page sent that can't go in the file; the message says why (never the value)."""


def _valid_password(value):
    if not isinstance(value, str) or not 1 <= len(value) <= PASSWORD_MAX:
        raise Invalid(f"a password is 1 to {PASSWORD_MAX} characters")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise Invalid("a password can't contain line breaks or control characters")
    if value != value.strip():
        raise Invalid("a password can't start or end with a space (the file trims them)")
    return value


def _valid_url(value):
    try:
        return notify.check_url(value)
    except notify.Invalid as e:
        raise Invalid(str(e)) from None


def _valid_token(value):
    if not isinstance(value, str) or not notify.TOKEN_RE.fullmatch(value):
        raise Invalid("a ntfy access token is letters, digits, '-', '_' and '.' (like tk_AgQd...)")
    return value


_VALIDATE = {"router": _valid_password, "mesh": _valid_password, "notify": _valid_url, "notify_2": _valid_url,
             "notify_token": _valid_token}


def _valid(key, value):
    if key in REMOVABLE and value == "":
        return None                      # remove the line
    return _VALIDATE[key](value)


def save_credentials(changes, path=None):
    """Write {"router", "mesh", "notify", "notify_2", "notify_token": ...} into the credentials
    file as GLINET_PASSWORD=, DECO_PASSWORD=, NOTIFY_URL=, NOTIFY_URL_2= and NOTIFY_TOKEN= lines
    ("" removes a notification line): every value valid or nothing is written; other lines are kept; the
    folder and file are created if needed; written to a temporary file and then swapped in, so a
    crash can't leave it half-written. Returns the keys set. Never logs or returns a value."""
    if not isinstance(changes, dict) or not changes:
        raise Invalid("expected the passwords to set")
    unknown = [k for k in changes if k not in CREDENTIAL_KEYS]
    if unknown:
        raise Invalid(f"{str(unknown[0])[:20]!r} isn't something Hearth keeps in its credentials file")
    new = {CREDENTIAL_KEYS[k]: _valid(k, v) for k, v in changes.items()}
    path = path or router.credentials_path()
    with _write_lock:
        return _write(path, new, changes)


def _write(path, new, changes):
    lines = []
    try:
        with open(path, encoding="utf-8-sig") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        pass
    except (OSError, UnicodeDecodeError) as e:
        raise Invalid(f"can't read the passwords file ({type(e).__name__})") from None
    kept = [ln for ln in lines if ln.strip().partition("=")[0].strip() not in new]
    out = kept + [f"{k}={v}" for k, v in new.items() if v is not None]   # None: the line is removed
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, mode=0o700, exist_ok=True)   # new folder: yours only (an existing one is left as it is)
    fd, tmp = tempfile.mkstemp(prefix=".router-", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(out) + "\n")
        os.replace(tmp, path)
    except OSError as e:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise Invalid(f"can't write the passwords file ({type(e).__name__})") from None
    return sorted(changes)
