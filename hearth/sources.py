"""What feeds Hearth, and whether each source works - one shape for every source, so the
dashboard, Home Assistant and (later) alerts read one place instead of each reader's own rows.

Each source has a state row "source:<name>":
    {configured, ok, since, last_ok, error, detail}
- configured: False = not set up (nothing to do, not a failure); then ok is None.
- ok: the last attempt worked.
- since: failing since (None while it works).
- last_ok: when it last worked (None if never).
- error: why the last attempt failed (never carries secrets: the readers' messages don't).
- detail: what the source reports about itself (address, link, ...), small and plain.
"""
import time

from . import store

PREFIX = "source:"
ROUTER, MESH, UPNP, DNS, NOTIFY, BACKUP = "router", "mesh", "upnp", "dns", "notify", "backup"
NAMES = (ROUTER, MESH, UPNP, DNS, NOTIFY, BACKUP)
PUBLIC = ("configured", "ok", "since", "last_ok", "error", "detail")


def _key(name):
    return PREFIX + name


def read(conn, name):
    """A source's state, or None if it never reported. A damaged row reads as None (it's only
    status: the next report rewrites it)."""
    st = store.get_state(conn, _key(name))
    return st if isinstance(st, dict) else None


def report_ok(conn, name, detail=None, now=None):
    """The source just worked."""
    store.set_state(conn, _key(name), {"configured": True, "ok": True, "since": None,
                                       "last_ok": now if now is not None else time.time(), "error": None, "detail": detail or {}})


def report_error(conn, name, error, now=None, detail=None):
    """The source is set up and just failed. Keeps when it last worked, and when the failing began."""
    now = now if now is not None else time.time()
    prev = read(conn, name) or {}
    failing_already = prev.get("configured") and prev.get("ok") is False and prev.get("since")
    store.set_state(conn, _key(name), {
        "configured": True, "ok": False, "since": prev["since"] if failing_already else now,
        "last_ok": prev.get("last_ok"), "error": str(error)[:200],
        "detail": detail if detail is not None else (prev.get("detail") or {})})


def report_unconfigured(conn, name, why=None):
    """The source isn't set up: not a failure. Readers that keep finding nothing (UPnP, once a
    minute) report the same thing each time, so an unchanged row isn't rewritten."""
    st = {"configured": False, "ok": None, "since": None, "last_ok": None,
          "error": None, "detail": {"why": why} if why else {}}
    if read(conn, name) != st:
        store.set_state(conn, _key(name), st)


def states(conn):
    """{name: state} for every source that has reported."""
    out = {}
    for name in NAMES:
        st = read(conn, name)
        if st is not None:
            out[name] = {k: st.get(k) for k in PUBLIC}
    return out


def failing(all_states):
    """How many set-up sources are failing."""
    return sum(1 for s in all_states.values() if s.get("configured") and s.get("ok") is False)
