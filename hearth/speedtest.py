"""Step 4, part 6 (#88): a speed test you start - how fast the line is, and how much lag it adds
when it's full ("bufferbloat"), which is what makes calls and games stutter while someone
downloads.

Download and upload go to speedtest_server (config.json only; default Cloudflare's speed test).
While each runs, Hearth's own pings keep going: the median round trip to the internet before the
test (idle) and during each direction (loaded) is the lag a full line adds. Nothing runs unless
a person starts it, or a schedule they set in config.json says so.

The endpoints (spike, 2026-10-20): GET <server>/__down?bytes=N and POST <server>/__up, which need
a named User-Agent - the default Python-urllib one gets 403."""
import os
import statistics
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

from . import levels as lv, router
from .config import CFG, inet_target

PHASE_S = 10.0            # each direction runs this long
WARMUP_S = 1.5            # the first part of each is connection setup: not counted
STREAMS_DOWN, STREAMS_UP = 4, 3
CHUNK = 64 * 1024
DOWN_BYTES = 50_000_000   # asked for per request; a stream asks again until the phase ends
UP_BYTES = 2_000_000
MIN_GAP_S = 60            # between the end of one test and the start of the next
MAX_PER_HOUR = 4          # however they're started: caps how much a busy (or hostile) client can fill the
                          # line, and how much of the hour's slow spells a test can take out of the record
IDLE_S = 30               # idle latency: the pings this long before the test
USER_AGENT = "Hearth/1 (home network monitor; speed test)"
TIMEOUT_S = 8             # a stalled stream gives up this soon (and stops counting at the phase's end)

_lock = threading.Lock()
_state = {"running": False, "phase": None, "started": None, "ended": 0.0, "error": None, "starts": []}


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """The test's URLs never redirect. Following one would let the server (or anyone on the path
    to it) send Hearth's requests over plain http, or to an address on your own network: refused."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, f"redirect to {newurl[:80]!r} refused", headers, fp)


_opener = urllib.request.build_opener(_NoRedirects)


class Busy(Exception):
    """A test is running, or the last one ended less than MIN_GAP_S ago."""


def server():
    """speedtest_server from config.json: an https URL, or the default."""
    s = CFG.get("speedtest_server") or "https://speed.cloudflare.com"
    u = urlparse(s)
    if u.scheme != "https" or not u.hostname:
        raise ValueError("speedtest_server must be an https:// address")
    return s.rstrip("/")


def state():
    with _lock:
        return dict(_state)


def _inet_median(conn, since, until):
    inet = [inet_target(ip) for ip in CFG["internet_targets"]]
    if not inet:
        return None
    marks = ",".join("?" * len(inet))
    rtts = [r for (r,) in conn.execute(f"SELECT rtt FROM pings WHERE ts >= ? AND ts < ? AND target IN ({marks}) "
                                       "AND rtt IS NOT NULL", (since, until, *inet))]
    return round(statistics.median(rtts), 1) if rtts else None


def _phase(fn, streams):
    """Run `streams` threads of fn(deadline, counter) for PHASE_S; Mb/s over the time after WARMUP_S."""
    start = time.monotonic()
    deadline = start + PHASE_S
    counted = [0] * streams
    errors = []

    def worker(i):
        def count(n):
            t = time.monotonic()
            if start + WARMUP_S <= t <= deadline:    # nothing after the phase ends counts
                counted[i] += n
        try:
            fn(deadline, count)
        except Exception as e:  # noqa: BLE001 - one stream failing is reported, the others carry on
            errors.append(e)
    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(streams)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(PHASE_S + TIMEOUT_S)
    took = max(0.1, min(time.monotonic(), deadline) - start - WARMUP_S)
    total = sum(counted)
    if not total and errors:
        raise errors[0]
    return round(total * 8 / took / 1e6, 1)


def _download(base):
    def run(deadline, count):
        while time.monotonic() < deadline:
            req = urllib.request.Request(f"{base}/__down?bytes={DOWN_BYTES}", headers={"User-Agent": USER_AGENT})
            with _opener.open(req, timeout=TIMEOUT_S) as r:
                while time.monotonic() < deadline:
                    chunk = r.read(CHUNK)
                    if not chunk:
                        break
                    count(len(chunk))
    return run


class _Counted:
    """The upload body as a file: each piece is counted as http.client takes it to send, so the
    bytes are counted when they go out - not all at once when the request finishes, which counted
    a request begun during the warm-up in full and overstated upload (#122: 11.3 Mb/s measured
    through a router shaping to 9)."""

    def __init__(self, body, count):
        self.body, self.pos, self.count = body, 0, count

    def read(self, n=-1):
        n = len(self.body) - self.pos if n is None or n < 0 else n
        piece = self.body[self.pos:self.pos + n]
        self.pos += len(piece)
        if piece:
            self.count(len(piece))
        return piece


def _upload(base):
    body = os.urandom(UP_BYTES)

    def run(deadline, count):
        while time.monotonic() < deadline:
            req = urllib.request.Request(f"{base}/__up", data=_Counted(body, count), method="POST",
                                         headers={"User-Agent": USER_AGENT, "Content-Type": "application/octet-stream",
                                                  "Content-Length": str(len(body))})
            with _opener.open(req, timeout=TIMEOUT_S) as r:
                r.read()
    return run


def start(db, now=None):
    """Claim the test (one at a time, MIN_GAP_S after the last) and run it in the background;
    `db` opens a connection. Busy if it can't start now."""
    now = now or time.time()
    with _lock:
        if _state["running"]:
            raise Busy("a speed test is already running")
        if now - _state["ended"] < MIN_GAP_S:
            raise Busy("wait a minute between speed tests (the line needs to settle)")
        recent = [t for t in _state["starts"] if now - t < 3600]
        if len(recent) >= MAX_PER_HOUR:
            raise Busy(f"at most {MAX_PER_HOUR} speed tests an hour - the next can start "
                       f"{time.strftime('%H:%M', time.localtime(min(recent) + 3600))}")
        _state.update(running=True, phase="starting", started=now, error=None, starts=[*recent, now])
    threading.Thread(target=_run, args=(db,), daemon=True, name="speedtest").start()


def _set(**kw):
    with _lock:
        _state.update(**kw)


# the longest a test can take: its window is stored with this end first, so if Hearth stops
# mid-test its lag is still not counted as the line's; the real end replaces it
LONGEST_S = 2 * (PHASE_S + TIMEOUT_S) + 5


def _run(db):
    conn = None
    started = time.time()
    try:
        conn = db()       # inside the try: if it can't open, "running" is still cleared below
        conn.execute("INSERT OR REPLACE INTO speedtests (ts, ended) VALUES (?, ?)", (started, started + LONGEST_S))
        conn.commit()
        base = server()
        idle = _inet_median(conn, started - IDLE_S, started)
        _set(phase="download")
        t0 = time.time()
        down = _phase(_download(base), STREAMS_DOWN)
        loaded_down = _inet_median(conn, t0 + WARMUP_S, time.time())
        _set(phase="upload")
        t1 = time.time()
        up = _phase(_upload(base), STREAMS_UP)
        loaded_up = _inet_median(conn, t1 + WARMUP_S, time.time())
        ended = time.time()
        g = lv.bufferbloat(idle, loaded_down, loaded_up)
        conn.execute("INSERT OR REPLACE INTO speedtests (ts, ended, down, up, idle_ms, loaded_down_ms, loaded_up_ms, grade, "
                     "server) VALUES (?,?,?,?,?,?,?,?,?)", (started, ended, down, up, idle, loaded_down, loaded_up, g["grade"],
                                                             urlparse(base).hostname))
        conn.commit()
        _set(error=None)
    except Exception as e:  # noqa: BLE001 - the page says what went wrong; nothing else depends on it
        _set(error=f"{type(e).__name__}: {str(e)[:160]}")
        try:
            if conn is None:
                raise RuntimeError("no database")
            conn.execute("INSERT OR REPLACE INTO speedtests (ts, ended, grade, server, error) VALUES (?,?,?,?,?)",
                         (started, time.time(), None, None, f"{type(e).__name__}: {str(e)[:160]}"))
            conn.commit()
        except Exception:  # noqa: BLE001
            pass
    finally:
        if conn is not None:
            conn.close()
        _set(running=False, phase=None, ended=time.time())


def view(conn):
    """/api/speedtest: whether one is running (and its phase), and the last 20 results."""
    cols = ("ts", "ended", "down", "up", "idle_ms", "loaded_down_ms", "loaded_up_ms", "grade", "server", "error")
    rows = [dict(zip(cols, r)) for r in conn.execute(f"SELECT {', '.join(cols)} FROM speedtests ORDER BY ts DESC LIMIT 20")]
    for r in rows:   # every row has the same keys: a failed test's level is unknown
        r.update(lv.bufferbloat(r["idle_ms"], r["loaded_down_ms"], r["loaded_up_ms"]) if r["grade"]
                 else {"level": lv.UNKNOWN, "why": r["error"] or "no pings to compare", "rise_ms": None})
    st = state()
    try:
        where, problem = urlparse(server()).hostname, None
    except ValueError as e:   # the same check a test makes: the page says it won't work, not "null"
        where, problem = None, str(e)
    # a row still without figures and no error is the test running now (or one Hearth stopped in)
    rows = [r for r in rows if r["grade"] or r["error"] or r["down"] is not None]
    return {"running": st["running"], "phase": st["phase"], "error": st["error"], "results": rows,
            "server": where, "server_problem": problem, "schedule": CFG.get("speedtest_schedule", "off"),
            # the router's traffic shaping (#122): a test can't go above it, so the page says so
            "shaping": (router.link_now(conn, time.time()) or {}).get("sqm")}


def windows(conn, since, until):
    """[(start, end)] of speed tests that overlap [since, until): their lag isn't the line's."""
    return conn.execute("SELECT ts, ended FROM speedtests WHERE ended >= ? AND ts < ?", (since, until)).fetchall()
