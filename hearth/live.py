"""Live mode: real-time figures while someone is actually looking at the dashboard.

The page asks /api/live every couple of seconds while it's visible (hidden tabs stop asking).
Each request keeps live mode on for LEASE_S. While it's on, the collectors that are cheap to
speed up do so - the router's traffic counters are read every few seconds, this computer is
sampled every few seconds - and when nobody is looking everything falls back to its usual
background pace. Pings never change: the latest results are just kept in memory and served
from there, so live mode adds no network traffic beyond one small router request every few
seconds.
"""
import threading
import time

LEASE_S = 30                # live mode lasts this long after the page's last request
ROUTER_INTERVAL_S = 5       # router traffic counters while live (background: a minute)
HOST_INTERVAL_S = 5         # this computer while live (background: a minute)

_lock = threading.Lock()
_until = 0.0
_latest = {}                # target id -> (ts, rtt or None): the last ping result
_host = None                # the last host sample taken while live


def touch(now=None):
    """A viewer is looking: keep live mode on for another LEASE_S."""
    global _until
    with _lock:
        _until = max(_until, (time.time() if now is None else now) + LEASE_S)


def active(now=None):
    with _lock:
        return (time.time() if now is None else now) < _until


def record_ping(tid, ts, rtt):
    """Called for every ping result; costs a dict write. No lock: a single item assignment (and
    the dict() copy in latest_pings) is atomic in CPython, and this runs on every ping."""
    _latest[tid] = (ts, rtt)


def latest_pings():
    return dict(_latest)


def set_host(sample, ts=None):
    """The latest host sample, stamped with when it was taken (None clears it)."""
    global _host
    _host = None if sample is None else (time.time() if ts is None else ts, sample)


def host_sample(max_age_s=None, now=None):
    """The latest host sample, or None if there's none or it's older than max_age_s - after
    live mode lapses and resumes, the last sample can be from before the gap."""
    h = _host
    if h is None:
        return None
    ts, sample = h
    if max_age_s is not None and (time.time() if now is None else now) - ts > max_age_s:
        return None
    return sample
