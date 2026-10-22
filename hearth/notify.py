"""Step 6, part 1 (#117): Hearth sends its own notifications - ntfy, Discord, Slack or any JSON
webhook - so a phone hears about a problem without Home Assistant.

What's sent (docs/superpowers/specs/2026-10-20-notifications-design.md):
- an alert when it's raised, once (alerts.run raises each problem once);
- its clearing, only for a BAD state alert that lasted CLEAR_MIN_S or more;
- everything waiting goes in one message, at most PER_HOUR messages an hour per channel;
- nothing raised (or cleared) more than WINDOW_S ago: after a stop or a long failure, old news
  is dropped, never sent late.

Channels are URLs in the credentials file (NOTIFY_URL=, NOTIFY_URL_2=, and NOTIFY_TOKEN= for a
ntfy access token) - secrets, handled like the router and mesh passwords: never logged, shown
or put in the API. Each channel keeps its own progress in a state row (what it has sent, when,
and how it's failing), so one failing channel neither blocks nor repeats the other."""
import http.client
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import levels as lv, router, settings, sources, store

URL_KEYS = ("NOTIFY_URL", "NOTIFY_URL_2")
TOKEN_KEY = "NOTIFY_TOKEN"
URL_MAX = 512
TOKEN_RE = re.compile(r"[A-Za-z0-9_\-.]{1,128}")
STATE_PREFIX = "notify:"          # + the channel's key: its progress
WINDOW_S = 3600                   # older news is dropped, not sent late
PER_HOUR = 6                      # messages a channel gets an hour, at most
CLEAR_MIN_S = 300                 # a BAD problem that lasted this long gets a "cleared" message
RETRY_S = (60, 300, 900)          # a failing channel is tried again after these (then every 15 min)
TIMEOUT_S = 10
REPLY_MAX = 4096                  # read of a reply: only for its status
LINES_MAX = 8                     # alerts listed in one message; the rest are "and N more"
LEVELS = (lv.WARN, lv.BAD)        # notify_level: the lowest level sent
NTFY, DISCORD, SLACK, WEBHOOK = "ntfy", "discord", "slack", "webhook"
KIND_NAMES = {NTFY: "ntfy", DISCORD: "Discord", SLACK: "Slack", WEBHOOK: "webhook"}
WAKE = threading.Event()          # set by the alerts loop when it has checked: look now
TEST_GAP_S = 60                   # Send a test (Setup): at most once a minute
_test = {"at": 0.0}
_test_lock = threading.Lock()


class Invalid(ValueError):
    """A channel URL or token that can't be used (the message never quotes the value)."""


class Busy(Exception):
    """A test was sent less than TEST_GAP_S ago."""


class SendError(Exception):
    """A send that failed; the message is a status or an error class, never the URL."""


def check_url(url):
    """A channel URL as given, or Invalid: http(s), a host, at most URL_MAX characters, no spaces
    or control characters. Plain http is allowed: a self-hosted ntfy on the home network."""
    if not isinstance(url, str) or not url or len(url) > URL_MAX:
        raise Invalid(f"a notification address is 1 to {URL_MAX} characters")
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in url):
        raise Invalid("a notification address has no spaces or control characters")
    try:
        u = urllib.parse.urlsplit(url)
        host = u.hostname
        u.port                     # a port that isn't a number (http://host:abc/) raises here
    except ValueError:
        raise Invalid("that notification address isn't a web address") from None
    if u.scheme not in ("http", "https") or not host:
        raise Invalid("a notification address starts with https:// (or http://) and names a server")
    if kind_of(url) == NTFY and not u.path.strip("/"):
        raise Invalid("a ntfy address ends with the topic, e.g. https://ntfy.sh/your-topic")
    return url


def kind_of(url):
    """Which kind of channel a URL is: ntfy (ntfy.sh, or a server whose name starts "ntfy", like
    ntfy.example.com), Discord, Slack, or any other JSON webhook."""
    u = urllib.parse.urlsplit(url)
    host = (u.hostname or "").lower()
    if host.startswith("ntfy"):
        return NTFY
    if host in ("discord.com", "discordapp.com") and u.path.startswith("/api/webhooks/"):
        return DISCORD
    if host == "hooks.slack.com":
        return SLACK
    return WEBHOOK


def channels(path=None):
    """[(key, url, kind)] set in the credentials file, and the ntfy token (or None). A line that
    isn't a usable URL is left out (and reported by run as a failing channel)."""
    path = path or router.credentials_path()
    out = []
    for key in URL_KEYS:
        try:
            url = router.read_password(path, key)
        except router.RouterError:
            continue
        if url:
            out.append((key, url, kind_of(url) if _usable(url) else None))
    try:
        token = router.read_password(path, TOKEN_KEY) or None
    except router.RouterError:
        token = None
    # it goes in a header: only token characters (a stray CR or space can't reach the request)
    return out, token if token and TOKEN_RE.fullmatch(token) else None


def _usable(url):
    try:
        check_url(url)
        return True
    except Invalid:
        return False


# ---------------------------------------------------------------------------- what's waiting
def _min_level():
    v = settings.value("notify_level")
    return v if v in LEVELS else lv.WARN


def news(conn, now, since):
    """What has happened since `since` (and within WINDOW_S): [{id, ev, level, text, kind, first,
    cleared}], ev "raise" or "clear", oldest first. A raise below notify_level is left out unless
    it's an event (an outage that ended, a new device: raised only when those alerts are on)."""
    lo = max(since, now - WINDOW_S)
    floor = lv.rank(_min_level())
    out = []
    for aid, level, text, kind, first, cleared in conn.execute(
            "SELECT id, level, text, kind, first, cleared FROM alerts WHERE first >= ? OR cleared >= ? ORDER BY id",
            (lo, lo)):
        row = {"id": aid, "level": level, "text": text, "kind": kind, "first": first, "cleared": cleared}
        if first >= lo and first <= now and (kind == "event" or lv.rank(level) >= floor):
            out.append({**row, "ev": "raise", "at": first})
        if (kind == "state" and cleared is not None and lo <= cleared <= now and level == lv.BAD
                and cleared - first >= CLEAR_MIN_S):
            out.append({**row, "ev": "clear", "at": cleared})
    return sorted(out, key=lambda n: (n["at"], n["id"]))


def _ev_key(n):
    return f"{n['ev'][0]}:{n['id']}"


# ---------------------------------------------------------------------------- the messages
def _lasted(s):
    m = max(1, round(s / 60))
    return f"{m} min" if m < 120 else f"{round(m / 60)} h"


def _line(n):
    if n["ev"] == "clear":
        return f"Cleared: {n['text']} (lasted {_lasted(n['cleared'] - n['first'])})"
    return f"{'Problem' if n['level'] == lv.BAD else 'Warning'}: {n['text']}"


def compose(items):
    """(title, lines, worst level of what was raised or None) for a batch of news."""
    raised = [n for n in items if n["ev"] == "raise"]
    if not raised:
        title = "Hearth: cleared" if len(items) == 1 else f"Hearth: {len(items)} problems cleared"
    elif len(raised) == 1:
        title = "Hearth: something needs you"
    else:
        title = f"Hearth: {len(raised)} things need you"
    lines = [_line(n) for n in items[:LINES_MAX]]
    if len(items) > LINES_MAX:
        lines.append(f"and {len(items) - LINES_MAX} more - see Hearth")
    return title, lines, lv.worst([n["level"] for n in raised]) if raised else None


def _cap(s, n):
    return s if len(s) <= n else s[:n - 1] + "…"


def build(kind, url, items, link=None, token=None):
    """(url to post to, headers, body bytes) for one message to one channel."""
    title, lines, worst = compose(items)
    text = "\n".join(lines)
    if kind == NTFY:
        # JSON to the server's root, the topic in the body: UTF-8 throughout (headers would be
        # latin-1 only, and alert texts carry names and °C)
        u = urllib.parse.urlsplit(url)
        base, _, topic = u.path.rstrip("/").rpartition("/")
        body = {"topic": topic, "title": title, "message": _cap(text, 3500),
                "priority": 4 if worst == lv.BAD else 3,
                "tags": ["rotating_light" if worst == lv.BAD else "warning" if worst else "white_check_mark"]}
        if link:
            body["click"] = link
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return urllib.parse.urlunsplit((u.scheme, u.netloc, base + "/", "", "")), headers, _json(body)
    if kind == DISCORD:
        return url, {}, _json({"content": _cap(f"**{title}**\n{text}" + (f"\n{link}" if link else ""), 2000)})
    if kind == SLACK:
        return url, {}, _json({"text": _cap(f"*{title}*\n{text}" + (f"\n<{link}|Open Hearth>" if link else ""), 3000)})
    body = {"title": title, "text": text, "level": worst, "link": link,
            "alerts": [{"event": n["ev"], "level": n["level"], "text": n["text"], "first": n["first"],
                        "cleared": n["cleared"]} for n in items[:LINES_MAX]], "more": max(0, len(items) - LINES_MAX)}
    return url, {}, _json(body)


def _json(obj):
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """A redirect could send the message over plain http, or to an address on the home network:
    refused (as for the speed test)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


_opener = urllib.request.build_opener(_NoRedirects)


def send(post_url, headers, body):
    """POST it; SendError("HTTP 403") and the like on failure - never the URL, never the text."""
    req = urllib.request.Request(post_url, data=body, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "Hearth", **headers})
    try:
        with _opener.open(req, timeout=TIMEOUT_S) as r:
            r.read(REPLY_MAX)
    except urllib.error.HTTPError as e:
        e.close()
        raise SendError(f"HTTP {e.code}") from None
    except urllib.error.URLError as e:
        reason = e.reason
        raise SendError("timed out" if isinstance(reason, TimeoutError) else
                        f"couldn't connect ({type(reason).__name__})") from None
    except (TimeoutError, OSError) as e:
        raise SendError("timed out" if isinstance(e, TimeoutError) else f"couldn't connect ({type(e).__name__})") from None
    except (http.client.HTTPException, ValueError) as e:
        # a garbled reply (BadStatusLine, IncompleteRead) or an address urllib can't use: this
        # channel failed - it mustn't escape run and stop the other channel (#120 review)
        raise SendError(f"bad reply or address ({type(e).__name__})") from None


def link():
    """The Alerts list on the dashboard's address, when dashboard_url is set; else None."""
    base = settings.value("dashboard_url")
    if not isinstance(base, str) or not settings.DASHBOARD_URL_RE.fullmatch(base):   # the page's own check
        return None
    return base.rstrip("/") + "/#/overview?item=alerts"


# ---------------------------------------------------------------------------- one step
def _state(conn, key, now):
    st = store.get_state(conn, STATE_PREFIX + key)
    if not isinstance(st, dict) or not isinstance(st.get("since"), (int, float)):
        # first sight of this channel: only what happens from now on (no burst of old alerts)
        st = {"since": now, "sent": {}, "times": [], "fails": 0, "next": 0, "error": None}
    return st


def run(conn, now=None, path=None):
    """Send what's waiting to each channel that may send now; record progress and the source's
    state. Returns {key: "sent"|"failed"|"waiting"|"nothing"}."""
    now = now if now is not None else time.time()
    chans, token = channels(path)
    if not chans:
        sources.report_unconfigured(conn, sources.NOTIFY, "no notification address set up")
        return {}
    out, errors = {}, []
    for key, url, kind in chans:
        st = _state(conn, key, now)
        if kind is None:
            out[key] = "failed"
            errors.append(f"{key}: not a usable address")
            continue
        st["sent"] = {k: t for k, t in st.get("sent", {}).items() if t >= now - 2 * WINDOW_S}
        st["times"] = [t for t in st.get("times", []) if t > now - 3600]
        todo = [n for n in news(conn, now, st["since"]) if _ev_key(n) not in st["sent"]]
        if not todo:
            # nothing (left) to send: a failure was about news that's gone now - it no longer
            # stands, so the source doesn't say "failing" for good (#120 review)
            st.update(fails=0, next=0, error=None)
            out[key] = "nothing"
        elif len(st["times"]) >= PER_HOUR or now < st.get("next", 0):
            out[key] = "waiting"
        else:
            try:
                send(*build(kind, url, todo, link(), token if kind == NTFY else None))
            except SendError as e:
                st["fails"] = st.get("fails", 0) + 1
                st["next"] = now + RETRY_S[min(st["fails"], len(RETRY_S)) - 1]
                st["error"] = str(e)
                out[key] = "failed"
            else:
                st["sent"].update({_ev_key(n): now for n in todo})
                st["times"].append(now)
                st.update(fails=0, next=0, error=None)
                out[key] = "sent"
        if st.get("error"):
            errors.append(f"{KIND_NAMES[kind]}: {st['error']}")
        store.set_state(conn, STATE_PREFIX + key, st)
        conn.commit()   # before the next channel's send: no write lock held across a slow request
    detail = {"channels": [KIND_NAMES.get(k, "unusable") if k else "unusable" for _, _, k in chans]}
    if errors:
        sources.report_error(conn, sources.NOTIFY, "; ".join(errors), now, detail)
    else:
        sources.report_ok(conn, sources.NOTIFY, detail, now)
    return out


def test(path=None, now=None):
    """Setup's "Send a test": a fixed message to every channel now (outside the hourly limit,
    which is for alerts), at most once every TEST_GAP_S. {"results": [{"kind", "ok", "error"}]};
    the error is a status, never the address."""
    now = now if now is not None else time.time()
    chans, token = channels(path)   # first: if this failed, the minute mustn't be used up (#121 review)
    with _test_lock:
        if now - _test["at"] < TEST_GAP_S:
            raise Busy(f"a test was sent under a minute ago - try again in {int(TEST_GAP_S - (now - _test['at'])) + 1} s")
        _test["at"] = now
    item = {"id": 0, "ev": "raise", "level": lv.WARN, "text": "Hearth test: notifications work.",
            "first": now, "cleared": None}
    results = []
    for _key, url, kind in chans:
        if kind is None:
            results.append({"kind": None, "ok": False, "error": "not a usable address"})
            continue
        try:
            send(*build(kind, url, [item], link(), token if kind == NTFY else None))
            results.append({"kind": KIND_NAMES[kind], "ok": True, "error": None})
        except SendError as e:
            results.append({"kind": KIND_NAMES[kind], "ok": False, "error": str(e)})
    return {"results": results}
