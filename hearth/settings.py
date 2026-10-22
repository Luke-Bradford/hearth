"""Step 4, part 5 (#88): the settings you can change in the page. A fixed allowlist - each key
with its own validation - stored in the state table and read on use, so a change needs no
restart. Everything else stays in config.json, which needs access to the machine: in
particular nothing here makes Hearth act on its own (the speed test schedule is read-only)."""
import ipaddress
import re
import threading
import time

from . import dns, net, store
from .config import CFG

STATE_KEY = "settings"
CACHE_S = 5
READ_ONLY = ("speedtest_schedule",)     # shown in the page, set only in config.json


class Invalid(ValueError):
    """A change the allowlist refuses; the message says why, for the page."""


def _lan():
    try:
        return ipaddress.ip_network(CFG["discovery_subnet"]) if CFG.get("discovery_subnet") else net.local_network()
    except (ValueError, OSError):
        return None


def _day(value, _ctx):
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 28:
        raise Invalid("the day a usage month starts must be a whole number from 1 to 28")
    return value


def _resolvers(value, ctx):
    if not isinstance(value, list) or not 1 <= len(value) <= dns.MAX_RESOLVERS:
        raise Invalid(f"give 1 to {dns.MAX_RESOLVERS} DNS resolvers")
    out = []
    for item in value:
        if item == dns.GATEWAY:
            out.append(item)
            continue
        if not isinstance(item, str) or not dns.allowed(item.strip(), ctx["gateway"], ctx["lan"]):
            raise Invalid(f"{str(item)[:40]!r} can't be asked: use \"gateway\" (your router), an address on your "
                          f"own network, or one of {', '.join(dns.PUBLIC_RESOLVERS)}")
        out.append(str(ipaddress.IPv4Address(item.strip())))
    if len(set(out)) != len(out):
        raise Invalid("each DNS resolver once")
    return out


def _probe_name(value, _ctx):
    if not dns.valid_name(value):
        raise Invalid("the DNS check's name must be a hostname: dot-separated parts of 1-63 letters, digits or "
                      "hyphens, not starting or ending with a hyphen")
    return value.rstrip(".")


def _bool(value, _ctx):
    if not isinstance(value, bool):
        raise Invalid("an alert is turned on (true) or off (false)")
    return value


def _notify_level(value, _ctx):
    if value not in ("warn", "bad"):
        raise Invalid('notifications are sent from "warn" (warnings and problems) or "bad" (problems only)')
    return value


# scheme, host, port and a plain path (e.g. /hearth): it's the start of the link in each message.
# No query, fragment or user name - the link's #/overview?item=alerts is Hearth's own
DASHBOARD_URL_RE = re.compile(r"https?://[A-Za-z0-9.\-]+(:\d{1,5})?(/[A-Za-z0-9._~\-/]*)?")


def _dashboard_url(value, _ctx):
    if value == "":
        return value
    if not isinstance(value, str) or not DASHBOARD_URL_RE.fullmatch(value):
        raise Invalid("the dashboard address is like http://192.168.1.60:8080 (or empty for no link)")
    return value.rstrip("/")


# key -> validator(value, context) returning the value to store, or raising Invalid
EDITABLE = {"usage_month_starts": _day, "dns_resolvers": _resolvers, "dns_probe_name": _probe_name,
            "alert_attention": _bool, "alert_outages": _bool, "alert_calls": _bool, "alert_new_devices": _bool,
            "notify_level": _notify_level, "dashboard_url": _dashboard_url}

_cache, _lock = {"at": 0.0, "vals": {}}, threading.Lock()


def _stored(conn):
    st = store.get_state(conn, STATE_KEY, {})   # a damaged or wrong-kind row reads as nothing changed
    return {k: v for k, v in st.items() if k in EDITABLE} if isinstance(st, dict) else {}


def overrides():
    """What's been changed in the page, re-read at most every CACHE_S (its own connection)."""
    with _lock:
        if time.time() - _cache["at"] > CACHE_S:
            conn = store.db()
            try:
                _cache["vals"] = _stored(conn)
            finally:
                conn.close()
            _cache["at"] = time.time()
        return dict(_cache["vals"])


def value(key):
    """A setting now: the page's value if one was set, else config.json's (or its default)."""
    o = overrides()
    return o[key] if key in o else CFG.get(key)


def view(conn):
    """/api/settings: the editable values now, what config.json says for each, the read-only ones."""
    o = _stored(conn)
    return {"values": {k: o.get(k, CFG.get(k)) for k in EDITABLE}, "changed": sorted(o),
            "defaults": {k: CFG.get(k) for k in EDITABLE},
            "read_only": {k: CFG.get(k, "off") for k in READ_ONLY},
            "public_resolvers": list(dns.PUBLIC_RESOLVERS)}


def update(conn, changes, gateway):
    """Apply {key: value} from the page: every key must be editable and every value valid, or
    nothing changes (Invalid says the first problem). A value of None puts a key back to
    config.json's. Returns the keys changed."""
    if not isinstance(changes, dict) or not changes:
        raise Invalid("expected an object of settings to change")
    unknown = [k for k in changes if k not in EDITABLE]
    if unknown:
        raise Invalid(f"{str(unknown[0])[:40]!r} can't be changed in the page")
    ctx = {"gateway": gateway, "lan": _lan()}
    new = _stored(conn)
    for k, v in changes.items():
        value = None if v is None else EDITABLE[k](v, ctx)
        # the page posts every field: one that's the same as config.json's isn't a change, so
        # it isn't kept as one (a later config.json edit still applies to it)
        if value is None or value == CFG.get(k):
            new.pop(k, None)
        else:
            new[k] = value
    store.set_state(conn, STATE_KEY, new)
    return sorted(changes)


def invalidate():
    """The next read goes to the database: call after the change is committed (before it, a
    reader in another thread could cache the old value again)."""
    with _lock:
        _cache["at"] = 0.0
