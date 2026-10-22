"""Read per-device traffic from the router, when it offers a local API.

Supported: GL.iNet firmware 4.x (JSON-RPC at http://<router>/rpc). Hearth finds the router
itself (the default gateway); the only thing you provide is the admin password, in a file
outside the repo - by default %USERPROFILE%\\.hearth\\router.env containing

    GLINET_PASSWORD=...

Security: the password is read from that file only at login and sent only to the router's
own LAN address (a private IP, no proxies, no redirects followed). It is never logged,
stored in the database or returned by the dashboard. The session id lives in memory only.
Everything the router returns is reduced to MAC, IP, name, online and byte counters (and, from
its status, temperature, uptime, load and memory) before it goes anywhere, so WiFi keys and
other settings never leave this module.
"""
import hashlib
import ipaddress
import json
import os
import re
import threading
import urllib.request

from . import store, upnp
from .config import CFG, DEFAULTS

DEFAULT_CREDENTIALS = os.path.join(os.path.expanduser("~"), ".hearth", "router.env")
MIN_INTERVAL_S = 15
ERROR_STATE_KEY = "router_error"  # state row: {since, error} while the router can't be read
MAX_RESPONSE = 4 * 1024 * 1024  # a client list is a few KB; refuse anything absurd
TIMEOUT_S = 15

# set by the dashboard's "Refresh now"; the router collector wakes up and polls
REFRESH = threading.Event()

_B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


class RouterError(Exception):
    """Never carries the password or a session id in its message."""


def poll_interval_s():
    """How often to read the router; a bad config value falls back to the default."""
    try:
        return max(MIN_INTERVAL_S, float(CFG["router_poll_interval_s"]))
    except (TypeError, ValueError):
        return float(DEFAULTS["router_poll_interval_s"])


PASSWORD_KEY = "GLINET_PASSWORD"   # the router's line in the credentials file (the mesh's is mesh.PASSWORD_KEY)


def credentials_path():
    return CFG.get("router_credentials_file") or DEFAULT_CREDENTIALS


def read_password(path, key=PASSWORD_KEY):
    """One KEY=value line from the credentials file (shared by the router and mesh readers)."""
    try:
        with open(path, encoding="utf-8-sig") as f:  # -sig: tolerate Notepad's byte-order mark
            for line in f:
                k, _, v = line.strip().partition("=")
                if k.strip() == key:
                    return v.strip().strip('"').strip("'")
    except (OSError, UnicodeDecodeError) as e:
        raise RouterError(f"can't read {path} ({type(e).__name__})") from None
    raise RouterError(f"{key} not found in {path}")


def has_password(path, key):
    try:
        read_password(path, key)
        return True
    except RouterError:
        return False


def sha256_crypt(password: bytes, salt: bytes, rounds: int = 5000) -> str:
    """SHA-256 crypt ($5$), per Ulrich Drepper's specification (what glibc crypt() does),
    which GL.iNet uses for its login challenge."""
    salt = salt[:16]
    plen = len(password)
    b = hashlib.sha256(password + salt + password).digest()
    a = hashlib.sha256(password + salt)
    for _ in range(plen // 32):
        a.update(b)
    a.update(b[:plen % 32])
    n = plen
    while n:
        a.update(b if n & 1 else password)
        n >>= 1
    a = a.digest()
    p = (hashlib.sha256(password * plen).digest() * (plen // 32 + 1))[:plen]
    s = (hashlib.sha256(salt * (16 + a[0])).digest() * (len(salt) // 32 + 1))[:len(salt)]
    c = a
    for i in range(rounds):
        h = hashlib.sha256()
        h.update(p if i & 1 else c)
        if i % 3:
            h.update(s)
        if i % 7:
            h.update(p)
        h.update(c if i & 1 else p)
        c = h.digest()
    out = []

    def b64(b2, b1, b0, n):
        w = (b2 << 16) | (b1 << 8) | b0
        for _ in range(n):
            out.append(_B64[w & 0x3F])
            w >>= 6

    for i, j, k in ((0, 10, 20), (21, 1, 11), (12, 22, 2), (3, 13, 23), (24, 4, 14),
                    (15, 25, 5), (6, 16, 26), (27, 7, 17), (18, 28, 8), (9, 19, 29)):
        b64(c[i], c[j], c[k], 4)
    b64(0, c[31], c[30], 3)
    prefix = "$5$" + (f"rounds={rounds}$" if rounds != 5000 else "")
    return prefix + salt.decode() + "$" + "".join(out)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None  # a redirect could carry the login hash somewhere else: refuse


_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


_MAC_RE = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}")


def _norm_mac(mac):
    """aa:bb:cc:dd:ee:ff, or None for anything that isn't a MAC (a junk row is dropped rather
    than becoming a device that can't be matched or renamed)."""
    m = str(mac).replace("-", ":").lower() if mac else ""
    return m if _MAC_RE.fullmatch(m) else None


def _int(v):
    try:
        return max(0, int(v))
    except (TypeError, ValueError):
        return None


def parse_clients(result):
    """The router's client list -> [{mac, ip, name, online, rx_total, tx_total}].
    rx = bytes the device downloaded, tx = bytes it uploaded (verified against this computer's
    own network counters). Rows without a MAC or counters are skipped."""
    rows = (result or {}).get("clients") if isinstance(result, dict) else None
    out = []
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, dict):
            continue
        mac, rx, tx = _norm_mac(r.get("mac")), _int(r.get("total_rx")), _int(r.get("total_tx"))
        if not mac or rx is None or tx is None:
            continue
        name = str(r.get("name") or "").strip()[:60] or None
        out.append({"mac": mac, "ip": str(r.get("ip") or "") or None, "name": name,
                    "online": bool(r.get("online")), "rx_total": rx, "tx_total": tx})
    return out


STATUS_STATE_KEY = "router_status"  # state row: the router's latest health reading, with its ts
RESTART_SLACK_S = 120               # clock and polling jitter allowed before calling it a restart


def _num(v, lo, hi):
    """A plausible number from the router, else None (bools and strings are refused)."""
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not lo <= v <= hi:
        return None
    return float(v)


def parse_status(result):
    """The router's system status -> {temp_c, uptime_s, load1, mem_used_pct}; whatever the
    firmware doesn't report is None. Nothing else (WiFi, addresses, services) is kept.
    Memory in use leaves out buffers and cache, which the system gives back when needed."""
    s = result.get("system") if isinstance(result, dict) else None
    s = s if isinstance(s, dict) else {}
    cpu = s.get("cpu") if isinstance(s.get("cpu"), dict) else {}
    temp = _num(cpu.get("temperature"), -40, 150)
    uptime = _num(s.get("uptime"), 0, 20 * 365 * 86400)
    la = s.get("load_average")
    load1 = _num(la[0], 0, 1000) if isinstance(la, list) and la else None
    total, free = _num(s.get("memory_total"), 1, 1e13), _num(s.get("memory_free"), 0, 1e13)
    cache = _num(s.get("memory_buff_cache"), 0, 1e13) or 0
    mem = round(min(100.0, max(0.0, 100 * (total - free - cache) / total)), 1) if total and free is not None else None
    return {"temp_c": temp, "uptime_s": int(uptime) if uptime is not None else None,
            "load1": load1, "mem_used_pct": mem}


LINK_STATE_KEY = "router_link"     # state row: the internet connection and shaping, as the router reports them
QDISC_RE = re.compile(r"[a-z_]{1,16}")
PROTOCOL_RE = re.compile(r"[a-z0-9_\-]{1,16}")


def parse_wan(result):
    """cable.get_status -> {protocol, connected, ip}: how the router reaches the internet (pppoe,
    dhcp...), whether it has an address there, and that address if it's a public one (a private
    or CGNAT one means another router is in front; not shown as the internet address)."""
    if not isinstance(result, dict):
        return None
    proto = str(result.get("protocol") or "")
    v4 = result.get("ipv4") if isinstance(result.get("ipv4"), dict) else {}
    raw = str(v4.get("ip") or "").strip().split("/")[0]   # given with its prefix length: "a.b.c.d/32"
    return {"protocol": proto if PROTOCOL_RE.fullmatch(proto) else None, "connected": bool(raw),
            "ip": upnp.public_ip(raw)}


def parse_sqm(result):
    """sqm.get_config -> {enabled, down_mbps, up_mbps, qdisc, autorate} or None. SQM (smart queue
    management) shapes traffic just under the line's speed so a busy line doesn't add lag; the
    limits are in Mbit/s (a speed test measured 43.4 against 45, #122)."""
    if not isinstance(result, dict) or not isinstance(result.get("enable"), bool):
        return None
    qdisc = str(result.get("qdisc") or "")
    return {"enabled": result["enable"], "down_mbps": _num(result.get("download"), 0, 100000),
            "up_mbps": _num(result.get("upload"), 0, 100000), "qdisc": qdisc if QDISC_RE.fullmatch(qdisc) else None,
            "autorate": result.get("autorate") is True}


SECURITY_STATE_KEY = "router_security"   # state row: the ways in from the internet, and the firmware (#131)
SECURITY_MAX_AGE_S = 3 * 3600            # read hourly; older isn't shown as how things are now
# (key, module, function): each read on its own - a firmware without one leaves that part None
SECURITY_CALLS = (("forwards", "firewall", "get_port_forward_list"), ("dmz", "firewall", "get_dmz"),
                  ("wan_access", "firewall", "get_wan_access"), ("upnp", "upnp", "get_config"),
                  ("cloud", "cloud", "get_config"), ("ddns", "ddns", "get_config"),
                  ("tailscale", "tailscale", "get_config"), ("zerotier", "zerotier", "get_config"),
                  ("wireguard", "wg-server", "get_status"), ("openvpn", "ovpn-server", "get_status"),
                  ("info", "system", "get_info"))
PORTS_RE = re.compile(r"\d{1,5}(-\d{1,5})?")
SHORT_TEXT_RE = re.compile(r"[\w .:+\-()/]{1,40}")


def _flag(d, key):
    """A true/false setting from a reply, or None (missing, or not a bool)."""
    v = d.get(key) if isinstance(d, dict) else None
    return v if isinstance(v, bool) else None


def _text(v, max_len=40):
    s = str(v or "").strip()[:max_len]
    return s if s and SHORT_TEXT_RE.fullmatch(s) else None


def _ports_ok(text):
    """'443' or '8000-8010', every port 1-65535 (#132 review)."""
    return bool(PORTS_RE.fullmatch(text)) and all(1 <= int(p) <= 65535 for p in text.split("-"))


def parse_forwards(result):
    """firewall.get_port_forward_list -> [{name, proto, port, to_ip, to_port, enabled}]. A rule
    Hearth can't read cleanly (an odd port list, a target that isn't a plain home address) is
    still a way in: it's kept as {"unreadable": True, "enabled", "name"} so the panel says so,
    never dropped - dropping it would show the home as more closed than it is (security review)."""
    rows = result.get("res") if isinstance(result, dict) else None
    out = []
    for r in rows if isinstance(rows, list) else []:
        if not isinstance(r, dict):
            out.append({"unreadable": True, "enabled": True, "name": None})
            continue
        enabled = r.get("enabled") is not False
        port, to_port = str(r.get("src_dport") or ""), str(r.get("dest_port") or "")
        try:
            to_ip = ipaddress.ip_address(str(r.get("dest_ip") or ""))
        except ValueError:
            to_ip = None
        home = to_ip is not None and to_ip.is_private and not (to_ip.is_loopback or to_ip.is_link_local)
        if not (home and _ports_ok(port) and _ports_ok(to_port or port)):
            out.append({"unreadable": True, "enabled": enabled, "name": _text(r.get("name"))})
            continue
        proto = " ".join(p for p in str(r.get("proto") or "").lower().split() if p in ("tcp", "udp")) or "tcp"
        out.append({"name": _text(r.get("name")), "proto": proto, "port": port, "to_ip": str(to_ip),
                    "to_port": to_port or port, "enabled": enabled})
    return out


def parse_security(raw):
    """{key: reply or None} from security() -> what can reach the home from the internet, and
    the firmware. Only on/off flags, forward rules and version text are kept - never a key,
    a token or an address on the other side."""
    wan = raw.get("wan_access") or {}
    cloud = raw.get("cloud") or {}
    info = raw.get("info") if isinstance(raw.get("info"), dict) else {}

    def server_on(r):   # a VPN server's status: 0 is stopped; anything else counts as running
        s = (r or {}).get("server", r) if isinstance(r, dict) else None
        st = s.get("status") if isinstance(s, dict) else None
        return None if not isinstance(st, int) or isinstance(st, bool) else st != 0
    return {
        "forwards": parse_forwards(raw.get("forwards")) if raw.get("forwards") is not None else None,
        "dmz": _flag(raw.get("dmz"), "enabled"),
        "admin_https": _flag(wan, "enable_https"), "admin_ssh": _flag(wan, "enable_ssh"),
        "ping": _flag(wan, "enable_ping"),
        "upnp": _flag(raw.get("upnp"), "enabled"),
        "cloud": _flag(cloud, "cloud_enable"), "cloud_ssh": _flag(cloud, "rtty_ssh"), "cloud_web": _flag(cloud, "rtty_web"),
        "ddns": _flag(raw.get("ddns"), "enable_ddns"),
        "tailscale": _flag(raw.get("tailscale"), "enabled"), "zerotier": _flag(raw.get("zerotier"), "enabled"),
        "wireguard": server_on(raw.get("wireguard")), "openvpn": server_on(raw.get("openvpn")),
        "firmware": {"version": _text(info.get("firmware_version"), 20), "date": _text(info.get("firmware_date"), 20),
                     "model": _text(info.get("model"), 20)} if info else None,
    }


def security_now(conn, now):
    """The latest security reading, or None when there's none in SECURITY_MAX_AGE_S."""
    st = store.get_state(conn, SECURITY_STATE_KEY)
    if not isinstance(st, dict) or not isinstance(st.get("ts"), (int, float)) or now - st["ts"] > SECURITY_MAX_AGE_S:
        return None
    return st


LINK_MAX_AGE_S = 600   # an older reading isn't shown as the connection now


def link_now(conn, now):
    """The latest {wan, sqm, ts} from the router, or None when there's none in LINK_MAX_AGE_S."""
    st = store.get_state(conn, LINK_STATE_KEY)
    if not isinstance(st, dict) or not isinstance(st.get("ts"), (int, float)) or now - st["ts"] > LINK_MAX_AGE_S:
        return None
    return st


def restarted(prev, prev_ts, cur, now):
    """Did the router boot since the previous health reading? Its boot time (reading time minus
    uptime) moves later only when it restarts - however long Hearth itself was off."""
    if not prev or prev.get("uptime_s") is None or cur.get("uptime_s") is None:
        return False
    return (now - cur["uptime_s"]) - (prev_ts - prev["uptime_s"]) > RESTART_SLACK_S


class GlinetRouter:
    """Logs in on first use and again whenever the session expires."""

    def __init__(self, host, password_file):
        ip = ipaddress.ip_address(host)  # raises on a hostname: we only talk to an address
        if not ip.is_private or ip.is_loopback or ip.is_link_local:
            raise RouterError(f"refusing to send credentials to {host}: not a LAN address")
        self.host = str(ip)
        self.url = f"http://{ip}/rpc"
        self.password_file = password_file
        self.user = "root"
        self._sid = None

    def _post(self, payload):
        req = urllib.request.Request(self.url, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"})
        try:
            with _opener.open(req, timeout=TIMEOUT_S) as r:
                body = r.read(MAX_RESPONSE + 1)
        except OSError as e:
            raise RouterError(f"router unreachable: {type(e).__name__}") from None
        if len(body) > MAX_RESPONSE:
            raise RouterError("router response too large")
        try:
            res = json.loads(body)
        except ValueError:
            raise RouterError("router sent something that isn't JSON") from None
        if not isinstance(res, dict):  # e.g. a captive page or a firmware quirk
            raise RouterError("router sent an unexpected reply")
        return res

    def login(self):
        ch = self._post({"jsonrpc": "2.0", "id": 1, "method": "challenge",
                         "params": {"username": self.user}}).get("result")
        if not isinstance(ch, dict) or ch.get("alg") != 5 or not ch.get("salt") or not ch.get("nonce"):
            raise RouterError("router doesn't offer a GL.iNet 4.x login")
        crypted = sha256_crypt(read_password(self.password_file).encode(), str(ch["salt"]).encode())
        method = hashlib.sha256 if ch.get("hash-method") == "sha256" else hashlib.md5
        digest = method(f"{self.user}:{crypted}:{ch['nonce']}".encode()).hexdigest()
        res = self._post({"jsonrpc": "2.0", "id": 2, "method": "login",
                          "params": {"username": self.user, "hash": digest}})
        sid = res["result"].get("sid") if isinstance(res.get("result"), dict) else None
        if not sid:
            raise RouterError("router login refused (check the password file)")
        self._sid = sid

    def call(self, module, func, params=None):
        for attempt in (1, 2):
            if not self._sid:
                self.login()
            res = self._post({"jsonrpc": "2.0", "id": 3, "method": "call",
                              "params": [self._sid, module, func, params or {}]})
            if "error" not in res:
                return res.get("result")
            self._sid = None  # expired or revoked session: log in again once
        code = (res.get("error") or {}).get("code") if isinstance(res.get("error"), dict) else None
        raise RouterError(f"{module}.{func} failed (code {code})")

    def clients(self):
        return parse_clients(self.call("clients", "get_list"))

    def status(self):
        return parse_status(self.call("system", "get_status"))

    def security(self):
        """parse_security() of every SECURITY_CALLS reply; a call this firmware doesn't offer, or
        that fails, leaves its part None. All reads."""
        raw = {}
        for key, module, func in SECURITY_CALLS:
            try:
                raw[key] = self.call(module, func)
            except RouterError:
                raw[key] = None
        return parse_security(raw)

    def link(self):
        """{wan, sqm}: each None when this firmware doesn't offer it or the call fails."""
        out = {}
        for key, (module, func), parse in (("wan", ("cable", "get_status"), parse_wan),
                                           ("sqm", ("sqm", "get_config"), parse_sqm)):
            try:
                out[key] = parse(self.call(module, func))
            except RouterError:
                out[key] = None
        return out


def counter_deltas(prev, cur):
    """Bytes moved since the last reading, per MAC.
    prev/cur: {mac: (rx_total, tx_total)}. A device seen for the first time only sets a
    baseline, and so does a counter that went backwards: it may have been reset to zero, but
    GL.iNet routers also restore slightly older saved totals after an outage, and counting
    those in full booked a device's whole lifetime as one reading. Re-baselining loses at most
    one reading after a real reset, and never over-counts."""
    out = {}
    for mac, (rx, tx) in cur.items():
        if mac not in prev:
            continue
        prx, ptx = prev[mac]
        drx = max(rx - prx, 0)
        dtx = max(tx - ptx, 0)
        if drx or dtx:
            out[mac] = (drx, dtx)
    return out
