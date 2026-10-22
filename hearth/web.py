"""Dashboard and JSON API.

Security model: this serves your home LAN with no login, like most home dashboards. Every
endpoint is read-only except three POSTs, all behind the same cross-site checks (JSON content
type and same-origin): /api/label, which can only set a display name (known key format,
60 printable characters, parameterised SQL, escaped by the dashboard); /api/router/refresh,
which takes no input and only asks for an early router reading; and /api/mesh/trust, which
only confirms the exact changed certificate the dashboard is showing (validated IP + SHA-256).
Router credentials never pass through this module.
Don't expose the port to the internet; use a VPN or Home Assistant's remote access instead.
"""
import functools
import ipaddress
import json
import os
import re
import socket
import sqlite3
import time
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

from . import (alerts, analysis, calls, digest, dns_health, levels, live, mesh, net, notify, overview, reports, router,
               security, settings, setup, speedtest, store)
from .config import CFG, DEFAULTS, HERE, log
from .naming import device_rows

_LABEL_KEY = re.compile(r"^(grp:\d{1,9}|dev:[0-9a-f]{2}(?::[0-9a-f]{2}){5}|dev:ip:\d{1,3}(?:\.\d{1,3}){3})$")
_MAX_BODY = 1024
DASHBOARD_FILE = "dashboard.html"
DASHBOARD_SCRIPT = "dashboard.js"    # the page's script, next to its markup
_STATIC = {"/": (DASHBOARD_FILE, "text/html; charset=utf-8"),
           "/index.html": (DASHBOARD_FILE, "text/html; charset=utf-8"),
           "/dashboard.js": (DASHBOARD_SCRIPT, "application/javascript"),
           "/chart.umd.js": ("chart.umd.js", "application/javascript")}
_LONG_CACHE = {"chart.umd.js"}       # a vendored library: cached a day; Hearth's own files always revalidated


class Handler(BaseHTTPRequestHandler):
    timeout = 15  # a client that stalls mid-request can't hold a handler thread for long

    def log_message(self, *a):
        pass

    def _send(self, body, ctype, code=200, cache=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        if cache:
            self.send_header("Cache-Control", cache)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(json.dumps(obj).encode(), "application/json", code)

    def _host_ok(self):
        if host_allowed(self.headers.get("Host")):
            return True
        self._json({"error": "unknown host name"}, 421)
        return False

    def do_GET(self):
        if not self._host_ok():
            return
        u = urlparse(self.path)
        if u.path in _STATIC:
            name, ctype = _STATIC[u.path]
            try:
                with open(os.path.join(HERE, name), "rb") as f:
                    body = f.read()
            except OSError:
                return self._json({"error": f"{name} is missing from the install"}, 404)
            # the dashboard is always revalidated, so a reload never shows an old version
            return self._send(body, ctype, cache="max-age=86400" if name in _LONG_CACHE else "no-cache")
        q = parse_qs(u.query)
        minutes = parse_minutes(q.get("minutes", ["60"])[0])
        if minutes is None:
            return self._json({"error": f"minutes must be a whole number from 1 to {MAX_MINUTES}"}, 400)
        conn = store.db()
        try:
            if u.path == "/api/summary":
                self._json(analysis.cached(analysis.summary, conn, snap(minutes, 1440)))
            elif u.path == "/api/series":
                self._json(analysis.cached(analysis.series, conn, snap(minutes)))
            elif u.path == "/api/incidents":
                # any range: before the last few hours, episodes come from storage (cheap)
                self._json(analysis.cached(analysis.incidents, conn, snap(minutes)))
            elif u.path == "/api/status":
                self._json(analysis.cached(analysis.status_view, conn, STATUS_KEY))
            elif u.path == "/api/devices":
                rows = sorted(device_rows(conn), key=lambda r: ipaddress.ip_address(r[1]))
                self._json([dict(zip(["id", "ip", "mac", "hostname", "vendor", "online", "first_seen",
                                      "last_seen", "name", "announced", "model", "state"], r)) for r in rows])
            elif u.path == "/api/events":
                rows = conn.execute("SELECT ts, kind, detail FROM events WHERE ts >= ? ORDER BY ts DESC LIMIT 200",
                                    (time.time() - minutes * 60,)).fetchall()
                self._json([dict(zip(["ts", "kind", "detail"], r)) for r in rows])
            elif u.path == "/api/live":
                # asked every few seconds by a visible page: keeps live mode on (faster router
                # and computer readings) for a short while; no input is used
                live.touch()
                self._json({**analysis.live_view(conn), "ui": dashboard_version()})
            elif u.path == "/api/overview":
                # the Overview tab: the last 24 hours and what needs attention (no parameters)
                self._json(overview.overview_view(conn))
            elif u.path == "/api/outages":
                # the outage log: days from a fixed set, so a client can't mint cache keys
                raw = q.get("days", ["30"])[0]
                # compared as exact text: isdigit() accepts "²", which int() then refuses
                if raw not in {str(d) for d in reports.OUTAGE_DAYS}:
                    self._json({"error": f"days must be one of {', '.join(map(str, reports.OUTAGE_DAYS))}"}, 400)
                else:
                    self._json(analysis.cached(reports.outages_view, conn, int(raw), ttl=reports.OUTAGES_TTL_S))
            elif u.path == "/api/report":
                # the ISP report card for a calendar month (default this one), at most 13 months back
                back = reports.months_back(q.get("month", [reports.this_month()])[0])
                if back is None:
                    self._json({"error": f"month must be YYYY-MM, this month or up to {reports.REPORT_MONTHS_BACK} before"}, 400)
                else:
                    self._json(analysis.cached(reports.report_view, conn, back, ttl=reports.REPORT_TTL_S))
            elif u.path == "/api/usage/month":
                # usage for a usage month (from the start day, usage_month_starts), up to 13 back
                back = reports.usage_months_back(q.get("month", [reports.current_usage_month()])[0])
                if back is None:
                    self._json({"error": f"month must be YYYY-MM, the current usage month or up to {reports.REPORT_MONTHS_BACK} before"}, 400)
                else:
                    self._json(analysis.cached(reports.usage_month_view, conn, back, ttl=reports.REPORT_TTL_S))
            elif u.path == "/api/kpi":
                self._json(analysis.cached(analysis.kpi_view, conn, STATUS_KEY))
            elif u.path == "/api/digest":
                # the newest weekly digest (no parameters)
                self._json({"digest": digest.latest(conn)})
            elif u.path == "/api/speedtest":
                self._json(speedtest.view(conn))
            elif u.path == "/api/alerts":
                self._json(alerts.view(conn))
            elif u.path == "/api/security":
                # what can reach the home from the internet, and the firmware (#131)
                self._json(analysis.cached(security.security_view, conn, 60, ttl=60))
            elif u.path == "/api/setup":
                # local: opened on the Hearth machine itself - only there can passwords be set
                self._json({**setup.checklist(conn), "local": self._local()})
            elif u.path == "/api/settings":
                self._json(settings.view(conn))
            elif u.path == "/api/quality":
                self._json(analysis.cached(calls.quality_view, conn, snap(minutes)))
            elif u.path == "/api/dns":
                self._json(analysis.cached(dns_health.dns_view, conn, snap(minutes)))
            elif u.path == "/api/host":
                self._json(analysis.cached(analysis.host_view, conn, snap(minutes)))
            elif u.path == "/api/mesh":
                self._json(analysis.cached(analysis.mesh_view, conn, snap(minutes)))
            elif u.path == "/api/usage":
                self._json(analysis.cached(analysis.usage, conn, snap(minutes)))
            elif u.path == "/api/wifi":
                self._json(analysis.cached(_wifi, conn, snap(minutes)))
            elif u.path == "/api/device/places":
                # where one device was over the range: id must be a device Hearth knows
                did = q.get("id", [""])[0]
                known = did.startswith("dev:") and len(did) <= 64 and (
                    label_target_exists(conn, did)
                    or conn.execute("SELECT 1 FROM device_places WHERE device = ? LIMIT 1", (did,)).fetchone())
                if not known:
                    self._json({"error": "no such device"}, 404)
                else:
                    self._json(analysis.device_places(conn, did, minutes))
            elif u.path == "/api/topology":
                hist = store.topology_history(conn, time.time())
                self._json({"current": store.topology_at(hist, time.time()),
                            "isp_path": store.get_state(conn, "isp_path")})
            else:
                self._json({"error": "not found"}, 404)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            conn.close()

    def _local(self):
        """Whether this request comes from the machine Hearth runs on (the TCP peer is loopback,
        which a device on the network can't fake)."""
        try:
            addr = ipaddress.ip_address(self.client_address[0])
        except (ValueError, IndexError, TypeError):
            return False
        mapped = getattr(addr, "ipv4_mapped", None)
        return (mapped or addr).is_loopback

    def _credentials(self, raw):
        """Router and mesh passwords from the Setup panel (#105): only from this machine itself,
        validated, written atomically, never echoed or logged; the readers are woken."""
        if not self._local():
            return self._json({"error": "passwords can only be set on the computer running Hearth "
                                        "(open the page there), or in the passwords file"}, 403)
        try:
            changes = json.loads(raw)
        except (ValueError, RecursionError):
            return self._json({"error": "expected the passwords to set"}, 400)
        try:
            changed = setup.save_credentials(changes)
        except setup.Invalid as e:
            return self._json({"error": str(e)}, 400)
        router.REFRESH.set()
        mesh.REFRESH.set()
        notify.WAKE.set()
        conn = store.db()
        try:
            try:   # saved already: a failed note in the log mustn't make it look as if it wasn't
                store.add_event(conn, "credentials", "Set from the Setup panel: " + ", ".join(
                    {"router": "the router password", "mesh": "the Deco password", "notify": "notification address 1",
                     "notify_2": "notification address 2", "notify_token": "the ntfy token"}[k] for k in changed))
                conn.commit()
            except sqlite3.Error as e:
                conn.rollback()
                log(f"setup: passwords saved; couldn't log it ({type(e).__name__})")
            return self._json({**setup.checklist(conn), "local": True})
        finally:
            conn.close()

    def _settings(self, raw):
        """Change settings from the page: only settings.EDITABLE keys, each validated; all or
        nothing. Logged as an event naming the keys (their values are in the settings themselves)."""
        try:
            changes = json.loads(raw)
        except (ValueError, RecursionError):   # RecursionError: deeply nested JSON within the size cap
            return self._json({"error": "expected a JSON object of settings"}, 400)
        conn = store.db()
        try:
            try:
                changed = settings.update(conn, changes, analysis._gateway_ip(conn))
            except settings.Invalid as e:
                return self._json({"error": str(e)}, 400)
            store.add_event(conn, "settings", "Settings changed in the page: " + ", ".join(changed))
            conn.commit()
            settings.invalidate()       # after the commit, so no reader caches the old value again
            analysis.clear_cache()      # views built from a setting (a usage month) show the change at once
            return self._json(settings.view(conn))
        finally:
            conn.close()

    def _trust(self, raw):
        """You confirmed a mesh unit's changed certificate. Accepted only for the exact pending
        (host, fingerprint) the dashboard showed you; anything else changes nothing."""
        parsed = _parse_trust(raw)
        if not parsed:
            return self._json({"error": "expected JSON {host, fingerprint}"}, 400)
        conn, failed = None, None
        try:
            conn = store.db()
            ok = mesh.trust(conn, *parsed)
        except sqlite3.OperationalError:  # e.g. the database is busy: the press can simply be retried
            failed = "busy - try again in a moment"
        except mesh.PinsDamaged as e:  # the message says how to recover
            failed = str(e)
        finally:
            if conn is not None:
                conn.close()  # before answering: the client may act on the answer straight away
        if failed:
            return self._json({"error": failed}, 503)
        analysis.clear_cache()
        if not ok:
            return self._json({"error": "nothing like that is waiting to be confirmed - reload the page"}, 409)
        return self._json({"ok": True})

    def do_POST(self):
        # Read the (small, capped) body before answering anything: replying and closing with
        # request bytes still unread makes Windows reset the connection, and the browser then
        # sees a failed request instead of our answer.
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > _MAX_BODY:
            self.close_connection = True
            return self._json({"error": "bad or too large body"}, 413)
        raw = self.rfile.read(length) if length else b""
        if not self._host_ok():
            return
        u = urlparse(self.path)
        if u.path not in ("/api/label", "/api/router/refresh", "/api/mesh/trust", "/api/settings",
                          "/api/alerts/seen", "/api/speedtest", "/api/setup/credentials", "/api/notify/test"):
            return self._json({"error": "not found"}, 404)
        # Block cross-site writes driven through a visitor's browser (CSRF). A JSON content
        # type can't be sent cross-origin without a CORS preflight, which this server never
        # approves; and a browser always sends Origin on POST, which must match our Host.
        if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != "application/json":
            return self._json({"error": "Content-Type must be application/json"}, 415)
        if not same_origin(self.headers.get("Origin"), self.headers.get("Host")):
            return self._json({"error": "cross-origin request refused"}, 403)
        if u.path == "/api/router/refresh":
            # takes no input: it only wakes the router reader, which enforces its own minimum
            # gap between readings, so repeated presses can't hammer the router
            router.REFRESH.set()
            mesh.REFRESH.set()
            return self._json({"ok": True})
        if u.path == "/api/mesh/trust":
            return self._trust(raw)
        if u.path == "/api/settings":
            return self._settings(raw)
        if u.path == "/api/setup/credentials":
            return self._credentials(raw)
        if u.path == "/api/notify/test":
            # takes no input: a fixed message to the owner's own channels, at most once a minute
            # (notify.test) - pressing it from another device only reaches the owner
            try:
                return self._json(notify.test())
            except notify.Busy as e:
                return self._json({"error": str(e)}, 429)
        if u.path == "/api/speedtest":
            # takes no input: starts a test unless one is running or the last ended under a
            # minute ago (speedtest.start), so the line can't be filled over and over from here
            try:
                speedtest.start(store.db)
            except speedtest.Busy as e:
                return self._json({"error": str(e)}, 409)
            return self._json({"started": True}, 202)
        if u.path == "/api/alerts/seen":
            # takes no input: marks every alert you've been shown as seen
            conn = store.db()
            try:
                alerts.mark_seen(conn)
                conn.commit()
                return self._json(alerts.view(conn))
            finally:
                conn.close()
        try:
            body = json.loads(raw)
            key, name = str(body.get("key", "")), str(body.get("name", "")).strip()
        except (ValueError, AttributeError):
            return self._json({"error": "expected JSON {key, name}"}, 400)
        if not _LABEL_KEY.match(key):
            return self._json({"error": "unknown key"}, 400)
        if len(name) > 60 or any(ord(ch) < 32 for ch in name):
            return self._json({"error": "name must be up to 60 printable characters"}, 400)
        conn = store.db()
        try:
            # only name things that exist, so the labels table can't be filled with junk keys
            if not (label_target_exists(conn, key) or key in store.labels(conn)):
                return self._json({"error": "no such device or group"}, 404)
            store.set_label(conn, key, name)
            conn.commit()
        finally:
            conn.close()
        analysis.clear_cache()
        self._json({"ok": True, "key": key, "name": name})


def dashboard_version():
    """When the dashboard's files last changed (markup and script): an open page compares this
    and reloads itself after an update, instead of carrying on with old code. Two file stats."""
    try:
        sts = [os.stat(os.path.join(HERE, f)) for f in (DASHBOARD_FILE, DASHBOARD_SCRIPT)]
    except OSError:
        return None  # e.g. mid-update: the page just skips the check this time
    # nanosecond time plus size, so a quick or time-preserving update still counts
    return "/".join(f"{st.st_mtime_ns}-{st.st_size}" for st in sts)


def _parse_trust(raw):
    """{host, fingerprint} from a trust request, validated, or None."""
    try:
        body = json.loads(raw)
        host, fp = str(body.get("host", "")), str(body.get("fingerprint", "")).lower()
        host = str(ipaddress.ip_address(host))
    except (ValueError, AttributeError):
        return None
    return (host, fp) if mesh.FINGERPRINT.fullmatch(fp) else None


def label_target_exists(conn, key):
    if key.startswith("grp:"):
        return conn.execute("SELECT 1 FROM groups WHERE id=?", (int(key[4:]),)).fetchone() is not None
    if any(r[0] == key for r in device_rows(conn)):
        return True
    # devices only the router knows (e.g. this computer) can be named from the traffic view
    if not key.startswith("dev:"):
        return False
    return conn.execute("SELECT 1 FROM router_clients WHERE mac=?", (key[4:],)).fetchone() is not None


MAX_MINUTES = 60 * 24 * 400
STATUS_KEY = 1  # one cache slot (2 s TTL) for /api/status, however often it's polled
# heavy endpoints only compute these windows (a request snaps up to the next one), so a
# client can't force thousands of distinct full recomputations
WINDOWS = (5, 15, 30, 60, 180, 360, 720, 1440, 4320, 10080, 43200, 129600, 525600, MAX_MINUTES)  # 525600: "1y"


def snap(minutes, cap=MAX_MINUTES):
    return next((w for w in WINDOWS if w >= min(minutes, cap)), cap)


def parse_minutes(raw):
    """Whole minutes in [1, MAX_MINUTES], or None. Rejects nan/inf/fractions so a client
    can't mint unlimited distinct cache keys."""
    try:
        m = int(raw)
    except (TypeError, ValueError):
        return None
    return m if 1 <= m <= MAX_MINUTES else None


@functools.lru_cache(maxsize=1)
def _own_names():
    """Worked out on first request rather than at import: getfqdn() can wait on DNS."""
    names = {"localhost"}
    for n in (socket.gethostname(), socket.getfqdn()):
        if n:
            short = n.split(".")[0].lower()
            names |= {n.lower(), short, short + ".local", short + ".lan", short + ".home.arpa"}
    names |= {h.lower() for h in CFG.get("allowed_hosts") or []}
    return names


def host_allowed(host):
    """Defence against DNS rebinding: a hostile site can point its own name at this server,
    making the browser treat it as same-origin. Only answer requests addressed to this
    machine by IP address, localhost or its own hostname (add others via allowed_hosts)."""
    if not host:
        return False
    name = host.strip().lower()
    if name.startswith("["):                       # [ipv6]:port
        name = name[1:].split("]", 1)[0]
    elif name.count(":") == 1:                     # name:port / ipv4:port
        name = name.rsplit(":", 1)[0]
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        return name in _own_names()


def same_origin(origin, host):
    """True when there is no Origin header (non-browser clients such as Home Assistant or
    curl) or when it names this server. `Origin: null` (sandboxed/file pages) has no netloc
    and is therefore refused."""
    if not origin:
        return True
    if not host:
        return False
    return urlparse(origin).netloc.lower() == host.lower()


# a radio not heard for this long is no longer "on air": unplugged access points disappear
# from the list instead of lingering with their last reading. At least 10 minutes, and never
# fewer than 3 scans, so one missed scan (or a slow scan interval) can't make radios flicker
def _scan_interval_s():
    try:  # a bad value in config.json must not stop the dashboard from loading
        return float(CFG["wifi_scan_interval_s"])
    except (TypeError, ValueError):
        return float(DEFAULTS["wifi_scan_interval_s"])


RECENT_RADIO_S = max(600, 3 * _scan_interval_s())


def _wifi(conn, minutes):
    """Latest reading per radio heard recently, with owner device name when we can match it."""
    names = {r[2]: r[8] for r in sorted(device_rows(conn), key=lambda r: (r[5] or 0, r[7] or 0)) if r[2]}
    macs = list(names)
    since = time.time() - minutes * 60
    rows = conn.execute(
        """SELECT w.ssid, w.bssid, w.band, w.channel, w.signal, w.util, w.stations, w.ts,
                  (SELECT AVG(util) FROM wifi a WHERE a.bssid = w.bssid AND a.ts >= ?),
                  (SELECT MAX(util) FROM wifi a WHERE a.bssid = w.bssid AND a.ts >= ?)
           FROM wifi w JOIN (SELECT bssid, MAX(ts) AS mts FROM wifi GROUP BY bssid) l
             ON w.bssid = l.bssid AND w.ts = l.mts
           WHERE w.ts >= ? ORDER BY w.band, w.ssid""", (since, since, time.time() - RECENT_RADIO_S)).fetchall()
    keys = ["ssid", "bssid", "band", "channel", "signal", "util", "stations", "ts", "util_avg", "util_max"]
    out = []
    for r in rows:
        o = dict(zip(keys, r))
        owner = net.radio_owner(o["bssid"], macs)
        o["ours"] = owner is not None
        o["name"] = names.get(owner, owner) if owner else (o["ssid"] or "(hidden network)")
        o["util_avg"] = round(o["util_avg"], 1) if o["util_avg"] is not None else None
        o.update(levels.channel_level(o["util"]))
        out.append(o)
    out.sort(key=lambda o: (not o["ours"], o["band"] or "", o["name"]))
    return out
