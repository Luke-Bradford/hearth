"""Read the real layout of a mesh WiFi system: which mesh node hangs off which (and over
what: cable or radio), and which node each device is connected to. Ping timing can't see
this - mesh nodes bridge at layer 2 - so when the mesh offers a local API, Hearth asks it.

Supported: TP-Link Deco (local HTTPS API of the main unit; the satellites only describe
themselves). Hearth finds the main unit among the devices it already knows; you provide the
password (the one the Deco app uses) as DECO_PASSWORD in the same credentials file as the
router password.

Security:
- Read-only: only the node list and client lists are requested.
- The password is read from the file only at login. It leaves this machine only RSA-
  encrypted with the Deco's key, inside the Deco's own login exchange, and only to a LAN
  address. Never logged, stored or shown; the session token lives in memory only.
- The Deco's HTTPS certificate is self-signed, so it is pinned on first use: its SHA-256
  fingerprint is remembered (only after a successful read) and every later connection must
  present the same certificate before anything is sent. A different certificate is refused
  (a reset Deco needs the pin cleared: delete the state row "mesh_pins").
- Who gets the password (find_candidates): the `mesh_host` you configure; else hosts pinned
  before; else devices whose MAC is registered to TP-Link - and once anything is pinned,
  such a device must present an already-pinned certificate (the main unit after a DHCP
  change) before the password is sent. Never a device just because of its name. On first
  setup a LAN attacker able to fake a TP-Link MAC could still receive it (the Deco protocol
  has the device supply the encryption key) - set `mesh_host` to rule that out.
- A refused password backs off for hours (some firmware locks out repeated failures).
- The main unit's identity is its two login keys (password encryption and request signing),
  recorded at the first successful reading with the MAC its address had. A login to a unit
  offering other keys stops before the password is even read (KeysChanged): you confirm it
  on the dashboard. An impostor can't learn the password or read anything without the real
  unit's private keys (and a stolen session token is refused without a valid signature,
  checked on a BE9300 - docs/superpowers/specs/deco-identity-observation.md).
- Main units change certificate every few hours while running, keeping their keys. A new
  certificate is accepted automatically (cert_decision) when the unit still offers the
  recorded keys - read without sending anything - and this computer's ARP table maps its
  address to the recorded MAC before and after the attempt (defence in depth: the public
  keys can be fetched by anyone). Anything else waits for you, with the reason.
  `mesh_auto_trust: false` makes every new certificate wait for you.
- Replies are reduced to MACs, IPs, names, roles, connection types and signal levels.
"""
import base64
import hashlib
import http.client
import ipaddress
import json
import random
import re
import ssl
import threading
import time
import urllib.parse

from . import config, crypto, store
from .levels import RSSI_FAIR, RSSI_GOOD, UNKNOWN, device_level
from .config import CFG, DEFAULTS
from .router import RouterError, read_password

PASSWORD_KEY = "DECO_PASSWORD"
PINS_STATE_KEY = "mesh_pins"     # {ip: sha256 of the Deco's certificate}
MESH_STATE_KEY = config.MESH_STATE_KEY  # latest snapshot (naming reads it too)
MESH_ERROR_KEY = "mesh_error"
CERT_PENDING_KEY = "mesh_cert_pending"   # {host, old, new, since, kind, reason, keys}: a change awaiting you
IDENTITY_STATE_KEY = "mesh_identity"     # {host, password, sign, mac, since}: the main unit's login keys
CERT_LOG_KEY = "mesh_cert_log"           # {day, count}: certificate changes accepted on that day
CERT_EVENTS_KEY = "mesh_cert_events"     # {host: ts}: when a change waiting for you was last logged
MAX_RESPONSE = 2 * 1024 * 1024
TIMEOUT_S = 15
USER = "admin"                   # what the Deco web login uses


class PinsDamaged(ValueError):
    """The saved certificate pins can't be read; the message says how to recover."""


class IdentityDamaged(PinsDamaged):
    """The saved login keys of the main unit can't be read; handled like damaged pins."""


def read_pins(conn):
    """{ip: certificate fingerprint}. A damaged pins row stops mesh reading with PinsDamaged
    (shown on the dashboard) rather than reading as "nothing pinned", which would trust
    whatever certificate is presented next."""
    try:
        pins = store.get_state(conn, PINS_STATE_KEY, {}, strict=True) or {}
    except ValueError:
        raise PinsDamaged(f"the saved certificate pins are unreadable - delete the state row "
                          f"{PINS_STATE_KEY!r} to trust the mesh afresh") from None
    if not isinstance(pins, dict):
        raise PinsDamaged(f"the saved certificate pins are malformed - delete the state row {PINS_STATE_KEY!r}")
    return pins


FINGERPRINT = re.compile(r"[0-9a-f]{64}")  # used with fullmatch (no trailing newline)
MAC_RE = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}")
KEY_NAMES = {"password": "password-encryption", "sign": "signing"}   # the two login keys, as shown


def key_fingerprint(pair):
    """SHA-256 of an RSA public key as the Deco hands it out before login: [modulus, exponent]
    in hex. Leading zeros and case don't change the key, so they don't change the fingerprint."""
    n, e = (str(x).strip().lower().lstrip("0") or "0" for x in pair[:2])
    return hashlib.sha256(f"{n}:{e}".encode()).hexdigest()


def read_identity(conn):
    """The main unit's identity - {host, password, sign, mac, since}: fingerprints of its two
    login keys, and the MAC its address had when they were recorded - or None before the first
    successful reading. Damaged reads as PinsDamaged, like the pins: never as "nothing recorded",
    which would let any keys be recorded afresh."""
    def damaged():
        return IdentityDamaged(f"the saved identity of the mesh's main unit is unreadable - delete the state row "
                               f"{IDENTITY_STATE_KEY!r} (Hearth records it again at the next reading)")
    try:
        ident = store.get_state(conn, IDENTITY_STATE_KEY, None, strict=True)
    except ValueError:
        raise damaged() from None
    if ident is None:
        return None
    if not (isinstance(ident, dict) and isinstance(ident.get("host"), str)
            and all(isinstance(ident.get(k), str) and FINGERPRINT.fullmatch(ident[k]) for k in KEY_NAMES)
            and (ident.get("mac") is None or (isinstance(ident["mac"], str) and MAC_RE.fullmatch(ident["mac"])))):
        raise damaged()
    return ident

REFRESH = threading.Event()      # "Refresh now" on the dashboard also re-reads the mesh
TRUSTED = threading.Event()      # you confirmed a changed certificate: try again straight away


class MeshError(RouterError):
    """Never carries the password, the session token or the session keys."""


class MeshTransportError(MeshError):
    """Couldn't talk to the device at all (unreachable, wrong certificate, HTTP error):
    logging in again won't help, so these are never retried within a reading."""


class CertChanged(MeshTransportError):
    """A pinned unit presented a different certificate (TP-Link regenerates it on reboot or
    firmware update - or something else is answering at that address). Nothing was sent.
    Only you can decide to trust the new one: the dashboard offers that."""

    def __init__(self, host, old, new):
        super().__init__(f"{host} presented a different certificate than before - refusing until you "
                         "confirm it on the dashboard")
        self.host, self.old, self.new = host, old, new


class KeysChanged(MeshTransportError):
    """The main unit offered login keys other than the ones recorded for it. Nothing - least
    of all the password - was sent. Only you can decide to trust the new keys."""

    def __init__(self, host, old, new, cert):
        which = " and ".join(KEY_NAMES[k] for k in KEY_NAMES if old.get(k) != new.get(k))
        super().__init__(f"{host} offered a different {which} key than before - refusing until you confirm "
                         "it on the dashboard")
        self.host, self.old, self.new, self.cert = host, old, new, cert


class MeshAuthError(MeshError):
    """The device refused the password. Retrying often could trip its login lockout."""


MIN_INTERVAL_S = 60


def poll_interval_s():
    try:
        return max(MIN_INTERVAL_S, float(CFG["mesh_poll_interval_s"]))
    except (TypeError, ValueError):
        return float(DEFAULTS["mesh_poll_interval_s"])


def _mac(v):
    return str(v).replace("-", ":").lower() if v else None


def _name(v):
    """Deco names are base64 (UTF-8); fall back to the raw text."""
    if not v:
        return None
    try:
        out = base64.b64decode(str(v), validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        out = str(v)
    out = "".join(ch for ch in out if ch.isprintable()).strip()
    return out[:60] or None


def _rand_digits(n):
    r = random.SystemRandom()
    return "".join(r.choice("0123456789") for _ in range(n))


class Deco:
    """One login session with a Deco. Re-logs in when the session expires."""

    def __init__(self, host, password_file, pins, identity=None):
        ip = ipaddress.ip_address(host)
        if not ip.is_private or ip.is_loopback or ip.is_link_local:
            raise MeshError(f"refusing to send credentials to {host}: not a LAN address")
        self.host = str(ip)
        self.password_file = password_file
        pins = pins or {}
        self.pin = pins.get(self.host)  # the certificate this host must present, if known
        # once any Deco is pinned, a new address is only trusted if it presents a certificate
        # Hearth already knows (the same unit, moved by DHCP); trust-on-first-use is setup only
        self.known = set(pins.values())
        self.new_pin = None   # proposed pin for a new address, kept by the caller only after success
        # the main unit's recorded login keys: login refuses any others before reading the password
        self.identity = identity
        self.keys = None      # {password, sign}: fingerprints of the keys this unit last offered
        self._stok = None
        self._cookies = {}

    # ------------------------------------------------------------------ transport
    def _post(self, path, body, form):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE   # self-signed: trust is the pinned fingerprint below
        conn = http.client.HTTPSConnection(self.host, 443, timeout=TIMEOUT_S, context=ctx)
        try:
            conn.connect()
            fp = hashlib.sha256(conn.sock.getpeercert(binary_form=True) or b"").hexdigest()
            expected = self.pin or self.new_pin
            if expected is None:
                if self.known and fp not in self.known:
                    raise MeshTransportError(f"{self.host} presented a certificate Hearth doesn't know - refusing "
                                             "(set mesh_host in config.json if your mesh was replaced or reset)")
                self.new_pin = fp     # this certificate must stay the same from now on
            elif expected != fp:
                raise CertChanged(self.host, expected, fp)
            data = urllib.parse.urlencode(body) if form else json.dumps(body)
            # the Deco's own web page labels its form-encoded body as JSON; do the same
            headers = {"Content-Type": "application/json"}
            if self._cookies:  # the session cookie set at login (memory only)
                headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self._cookies.items())
            conn.request("POST", path, body=data.encode(), headers=headers)
            r = conn.getresponse()
            for c in r.headers.get_all("Set-Cookie") or []:
                k, _, v = c.split(";")[0].partition("=")
                if k.strip():
                    self._cookies[k.strip()] = v.strip()
            raw = r.read(MAX_RESPONSE + 1)
            if r.status != 200:
                raise MeshTransportError(f"{self.host} answered HTTP {r.status}")
        except (OSError, http.client.HTTPException) as e:
            raise MeshTransportError(f"{self.host} unreachable: {type(e).__name__}") from None
        finally:
            conn.close()
        if len(raw) > MAX_RESPONSE:
            raise MeshError("reply too large")
        try:
            res = json.loads(raw)
        except ValueError:
            raise MeshError("reply isn't JSON") from None
        if not isinstance(res, dict):
            raise MeshError("unexpected reply")
        return res

    def _encrypted(self, path, payload):
        data = base64.b64encode(crypto.aes_cbc_encrypt(self._key.encode(), self._iv.encode(),
                                                       json.dumps(payload).encode())).decode()
        # every request carries the session keys in its signature (verified against a BE9300:
        # the shorter "h=..&s=.." form is refused after login)
        sign = f"k={self._key}&i={self._iv}&h={self._hash}&s={self._seq + len(data)}"
        res = self._post(path, {"sign": crypto.rsa_encrypt(*self._sign_key, sign.encode(), chunked=True),
                                "data": data}, form=True)
        if "data" not in res:
            return res
        try:
            out = json.loads(crypto.aes_cbc_decrypt(self._key.encode(), self._iv.encode(),
                                                    base64.b64decode(res["data"])))
        except ValueError:
            raise MeshError("couldn't decrypt the reply") from None
        if not isinstance(out, dict):
            raise MeshError("unexpected reply")
        return out

    # ------------------------------------------------------------------ session
    def _read_keys(self):
        """The two public keys the unit hands out before login, and the signing sequence start.
        Asking for them sends nothing secret."""
        keys = self._post("/cgi-bin/luci/;stok=/login?form=keys", {"operation": "read"}, form=False)
        auth = self._post("/cgi-bin/luci/;stok=/login?form=auth", {"operation": "read"}, form=False)
        try:
            pw_key = [str(x) for x in keys["result"]["password"][:2]]
            sign_key = [str(x) for x in auth["result"]["key"][:2]]
            seq = int(auth["result"]["seq"])
            if len(pw_key) < 2 or len(sign_key) < 2:
                raise ValueError("short key")
        except (KeyError, TypeError, ValueError, IndexError):
            raise MeshError("this device doesn't offer a Deco login") from None
        self.keys = {"password": key_fingerprint(pw_key), "sign": key_fingerprint(sign_key)}
        return pw_key, sign_key, seq

    def read_keys(self):
        """{password, sign}: fingerprints of the unit's login keys, without logging in."""
        self._read_keys()
        return dict(self.keys)

    def login(self):
        self._cookies = {}
        pw_key, self._sign_key, self._seq = self._read_keys()
        if self.identity and any(self.keys[k] != self.identity[k] for k in KEY_NAMES):
            # checked before the password is even read: it's never encrypted to keys we don't know
            raise KeysChanged(self.host, {k: self.identity[k] for k in KEY_NAMES}, dict(self.keys),
                              self.pin or self.new_pin)
        password = read_password(self.password_file, PASSWORD_KEY)
        self._key, self._iv = _rand_digits(16), _rand_digits(16)
        self._hash = hashlib.md5((USER + password).encode()).hexdigest()
        try:
            enc = crypto.rsa_encrypt(*pw_key, password.encode())
        except ValueError:
            raise MeshError("unexpected login key") from None
        res = self._encrypted("/cgi-bin/luci/;stok=/login?form=login",
                              {"params": {"password": enc}, "operation": "login"})
        stok = (res.get("result") or {}).get("stok") if isinstance(res.get("result"), dict) else None
        if not stok or not str(stok).isalnum():
            raise MeshAuthError(f"login refused (error {res.get('error_code')}; check {PASSWORD_KEY})")
        self._stok = str(stok)

    def call(self, form, payload, relogin=True):
        """One read. If the Deco answers with an error (an expired session), log in again once
        (unless relogin=False); transport and certificate errors are raised straight away."""
        res = None
        for _ in ((1, 2) if relogin else (1,)):
            if not self._stok:
                self.login()
            res = self._encrypted(f"/cgi-bin/luci/;stok={self._stok}/admin/{form}", payload)
            if res.get("error_code") == 0:
                result = res.get("result")
                return result if isinstance(result, dict) else {}
            if relogin:
                self._stok = None
        raise MeshError(f"{form.split('?')[0]} refused (error {res.get('error_code')})")

    # ------------------------------------------------------------------ data
    def snapshot(self):
        """{"nodes": [...], "clients": [...]} or raises MeshError when this isn't the main unit."""
        try:
            nodes = parse_nodes(self.call("device?form=device_list", {"operation": "read"}))
            if not any(n["role"] == "main" for n in nodes):
                raise MeshError(f"{self.host} is a satellite, not the main unit")
            clients = []
            for n in nodes:
                # the session was just proven by device_list: a refusal here is about that node
                # (e.g. an offline satellite), so it has no clients - not a reason to log in again
                try:
                    res = self.call("client?form=client_list",
                                    {"operation": "read", "params": {"device_mac": n["mac_raw"]}}, relogin=False)
                except MeshTransportError:
                    raise
                except MeshError:
                    res = {}
                clients += parse_clients(res, n["mac"])
            for n in nodes:
                n.pop("mac_raw")
            return {"nodes": link_parents(nodes), "clients": clients}
        except (TypeError, AttributeError, KeyError, ValueError) as e:  # a reply shaped unlike any Deco's
            raise MeshError(f"unexpected reply from {self.host} ({type(e).__name__})") from None


def parse_nodes(result):
    out, rows = [], (result or {}).get("device_list") if isinstance(result, dict) else None
    for d in rows if isinstance(rows, list) else []:
        if not isinstance(d, dict) or not d.get("mac"):
            continue
        conn = d.get("connection_type")
        conn = [str(c) for c in conn] if isinstance(conn, list) else []
        main = d.get("role") == "master"
        sig = d.get("signal_level") if isinstance(d.get("signal_level"), dict) else {}
        bands = [c[:12] for c in conn if c.startswith("band")][:4]
        out.append({
            "mac": _mac(d["mac"]), "mac_raw": str(d["mac"]), "ip": str(d.get("device_ip") or "") or None,
            "name": _name(d.get("nickname")), "model": str(d.get("device_model") or "")[:30] or None,
            "role": "main" if main else "satellite",
            "device_id": str(d.get("device_id") or "") or None,
            "parent_id": None if main else (str(d.get("parent_device_id") or "") or None),
            # the main unit's uplink is the cable to the router; a satellite's is its backhaul
            "backhaul": "wired" if main or "wired" in conn else ("wireless" if conn else "unknown"),
            "bands": bands,
            "signal": {str(k)[:12]: int(v) for k, v in sig.items() if re.fullmatch(r"[0-9]{1,2}", str(v))},
            # the backhaul's real signal strength (dBm) and link rates (Mb/s), per band in use
            "rssi": _per_band(d.get("signal_strength"), bands, -110, -10),
            "rate_rx": _per_band(d.get("rx_rate_list"), bands, 1, 20000),
            "rate_tx": _per_band(d.get("tx_rate_list"), bands, 1, 20000),
            "online": d.get("group_status") == "connected" or main,
            # its firmware, e.g. "1.3.5 Build 26071712 Rel. 18941" (#131: the Security panel)
            "firmware": fw if (fw := str(d.get("software_ver") or "").strip()[:40]) and FIRMWARE_RE.fullmatch(fw) else None,
        })
    return out


def _per_band(values, bands, lo, hi):
    """{band: int} for the bands in use, keeping only plausible numbers."""
    if not isinstance(values, dict):
        return {}
    out = {}
    for b in bands:
        v = values.get(b)
        if isinstance(v, (int, float)) and not isinstance(v, bool) and lo <= v <= hi:
            out[b] = int(v)
    return out


# --------------------------------------------------------------------------- judging link quality
RATE_DROP = 0.5                    # a link rate below half its usual is worth a look
BAND_NAMES = {"band2_4": "2.4 GHz", "band5": "5 GHz", "band6": "6 GHz"}


def rssi_grade(dbm):
    if dbm is None:
        return None
    return "good" if dbm >= RSSI_GOOD else "fair" if dbm >= RSSI_FAIR else "poor"


def backhaul_findings(node, usual_rates=None, usual_tx=None):
    """Plain-language problems with a satellite's link to the rest of the mesh:
    [(level, text)]. usual_rates / usual_tx: {band: median rx / tx rate over the last day}."""
    if node.get("role") == "main":
        return []
    name, out = node.get("name") or node["mac"], []
    if not node.get("online"):
        return [("bad", f"{name} is not connected to the mesh.")]
    if node.get("backhaul") == "wired":
        return []
    bands = node.get("bands") or []
    if bands and all(b == "band2_4" for b in bands):
        out.append(("warn", f"{name} is linked to the mesh on 2.4 GHz only - slow and crowded. It may be too "
                            "far from the next unit, or the 5/6 GHz link dropped."))
    rssi = node.get("rssi") or {}
    if rssi:
        best_band, best = max(rssi.items(), key=lambda kv: kv[1])
        if rssi_grade(best) == "poor":
            out.append(("bad", f"{name}'s link to the mesh is weak ({best} dBm at best, on "
                               f"{BAND_NAMES.get(best_band, best_band)}). Moving it closer to the unit it links "
                               "to would help."))
        elif rssi_grade(best) == "fair":
            out.append(("warn", f"{name}'s link to the mesh is only fair ({best} dBm at best)."))
    for key, usual_by_band, way in (("rate_rx", usual_rates, "receiving"), ("rate_tx", usual_tx, "sending")):
        for band, usual in (usual_by_band or {}).items():
            now = (node.get(key) or {}).get(band)
            if now is not None and usual and now < usual * RATE_DROP:
                out.append(("warn", f"{name}'s {BAND_NAMES.get(band, band)} link is {way} at {now} Mb/s, under "
                                    f"half its usual {usual} Mb/s."))
    return out


_GRADE = {"ok": "good", "warn": "fair", "bad": "poor"}


def device_quality(stats, node_stats, sleepy=False):
    """(grade, reason) for a wireless device - good / fair / poor / sleepy / None - from the one
    rule in levels.device_level (kept for the page's wording: "power saving", grade names)."""
    r = device_level(stats, node_stats, sleepy)
    if r["level"] == UNKNOWN:
        return ("sleepy" if r.get("power_saving") else None), r["why"]
    return _GRADE[r["level"]], r["why"]


_KIND = re.compile(r"^[a-z0-9_]{1,20}$")  # the mesh's device type, as stored and shown
NETWORKS = ("main", "guest", "iot")         # a Deco client's "interface": which of its networks it's on
FIRMWARE_RE = re.compile(r"[\w .\-()]{1,40}")


def parse_clients(result, node_mac):
    out, rows = [], (result or {}).get("client_list") if isinstance(result, dict) else None
    for c in rows if isinstance(rows, list) else []:
        if not isinstance(c, dict) or not c.get("mac") or not c.get("online"):
            continue
        link = str(c.get("connection_type") or "")
        kind = str(c.get("client_type") or "").lower()
        out.append({"mac": _mac(c["mac"]), "ip": str(c.get("ip") or "") or None, "node": node_mac,
                    "link": "wired" if link == "wired" else link[:12] if link.startswith("band") else "unknown",
                    "name": _name(c.get("name")),
                    # the mesh's own guess at what the device is (phone, pc, ...)
                    "kind": kind if _KIND.match(kind) and kind != "other" else None,
                    # which of the mesh's networks it's on: the main one, the guest or the IoT one (#122)
                    "network": iface if (iface := str(c.get("interface") or "")) in NETWORKS else None})
    return out


def link_parents(nodes):
    """Resolve each satellite's parent to a node MAC (the main unit when it can't be told)."""
    by_id = {n["device_id"]: n["mac"] for n in nodes if n.get("device_id")}
    main = next((n["mac"] for n in nodes if n["role"] == "main"), None)
    for n in nodes:
        parent_id = n.pop("parent_id", None)
        n.pop("device_id", None)
        n["parent"] = None if n["role"] == "main" else by_id.get(parent_id, main)
    return nodes


_TPLINK = re.compile(r"tp-?\s?link", re.I)


def auto_trust_enabled():
    """Accept a main unit's new certificate by itself when its address still maps to its MAC
    (default on). Off for false / "false" / "0" / "no" / "off"; anything else - including a
    missing or null setting - means the default, on."""
    v = CFG.get("mesh_auto_trust", DEFAULTS.get("mesh_auto_trust", True))
    return v is not False and str(v).lower() not in ("false", "0", "no", "off")


def cert_decision(identity, keys, mac_before, mac_after, auto):
    """Should the main unit's new certificate be accepted without asking you?
    -> ("accept", None) or ("ask", why), why being shown to you as is.

    Accepted only when all of it holds: automatic acceptance is on; the unit offers the same two
    login keys Hearth recorded for it (keys: what it offered with the new certificate, read
    without sending anything; None if that read failed); and its address mapped to the recorded
    MAC in this computer's ARP table both before and after the attempt. The keys are what
    protects the password, so they are the identity; the MAC check is defence in depth, since
    anyone can fetch the public keys. Anything missing or unreadable means asking."""
    if not auto:
        return "ask", "automatic acceptance is turned off (mesh_auto_trust)"
    if not identity:
        return "ask", "Hearth hasn't recorded this unit's login keys yet"
    if keys is None:
        return "ask", "its login keys couldn't be read to check it"
    changed = [KEY_NAMES[k] for k in KEY_NAMES if keys.get(k) != identity.get(k)]
    if changed:
        return "ask", f"its {' and '.join(changed)} key changed too"
    mac = identity.get("mac")
    if not mac:
        return "ask", "the unit's MAC hasn't been recorded yet"
    for when, seen in (("before", mac_before), ("after", mac_after)):
        if not seen:
            return "ask", f"its address wasn't in this computer's ARP table {when} the check"
        if seen != mac:
            return "ask", f"its address belonged to MAC {seen} {when} the check, not to the unit's {mac}"
    return "accept", None


def pending_cert(conn):
    """The change awaiting confirmation (a new certificate, or new login keys), with what helps
    you judge it: why Hearth didn't accept it by itself, and whether the device at that address
    still has the MAC recorded for the main unit."""
    p = store.get_state(conn, CERT_PENDING_KEY)
    if not p:
        return None
    snap = store.get_state(conn, MESH_STATE_KEY) or {}
    try:
        ident = read_identity(conn)
    except IdentityDamaged:
        ident = None   # the banner still shows; the reader reports the damage itself
    known = (ident or {}).get("mac") or next((n["mac"] for n in snap.get("nodes", []) if n.get("ip") == p["host"]),
                                             None)
    row = conn.execute("SELECT mac FROM devices WHERE ip = ?", (p["host"],)).fetchone()
    now_mac = _mac(row[0]) if row and row[0] else None
    return {"host": p["host"], "old": p["old"], "new": p["new"], "since": p["since"],
            "kind": p.get("kind") or "cert", "reason": p.get("reason"),
            "name": next((n.get("name") for n in snap.get("nodes", []) if n.get("ip") == p["host"]), None),
            "mac_before": known, "mac_now": now_mac,
            "same_device": bool(known and now_mac and known == now_mac)}


def trust(conn, host, fingerprint):
    """You confirmed the pending change: pin its certificate and, if it came with new login keys,
    record those as the main unit's identity. Only the exact pending (host, fingerprint) is
    accepted, so a stale page can't trust something else. Your confirmation also re-anchors the
    unit's MAC: it's recorded afresh at the next successful reading (a replaced unit has a new
    one). One write transaction, so a reading saving state at the same moment can't undo it.
    Returns True if pinned."""
    if conn.in_transaction:
        conn.commit()
    try:
        conn.execute("BEGIN IMMEDIATE")   # busy: OperationalError, which the endpoint answers 503
        p = store.get_state(conn, CERT_PENDING_KEY)
        if not p or p.get("host") != host or p.get("new") != fingerprint:
            conn.rollback()
            return False
        pins = read_pins(conn)
        ident = read_identity(conn)
        # only a change shown to you as new login keys records new keys
        keys = p.get("keys") if p.get("kind") == "keys" and isinstance(p.get("keys"), dict) else None
        if keys and all(isinstance(keys.get(k), str) and FINGERPRINT.fullmatch(keys[k]) for k in KEY_NAMES):
            ident = {"host": host, **{k: keys[k] for k in KEY_NAMES}, "mac": None, "since": time.time()}
        elif ident:
            ident = {**ident, "host": host, "mac": None}
        pins[host] = fingerprint
        store.set_state(conn, PINS_STATE_KEY, pins)
        if ident:
            store.set_state(conn, IDENTITY_STATE_KEY, ident)
        store.set_state(conn, CERT_PENDING_KEY, None)
        what = "login keys" if p.get("kind") == "keys" else "security certificate"
        store.add_event(conn, config.EV_MESH, f"You trusted the new {what} of the mesh's main unit ({host})")
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    TRUSTED.set()
    return True


def find_candidates(conn, pins, vendor_of):
    """LAN addresses the password may be sent to, most trusted first.

    The password is only ever offered to:
    - the address set as `mesh_host` in config.json, if any (your explicit choice); else
    - addresses already pinned (a Deco that has worked before - its certificate must match); else,
      on first setup only, devices whose MAC belongs to TP-Link in the IEEE register.
    Names are never trusted: any device can call itself "deco". vendor_of(mac) -> maker name."""
    configured = CFG.get("mesh_host")
    if configured:
        return [str(configured)]
    last = store.get_state(conn, "mesh_host")
    out = sorted(pins, key=lambda ip: ip != last)
    # TP-Link devices by MAC maker: on first setup, trusted on first use; afterwards only if
    # they present a certificate already pinned (the main unit after a DHCP address change)
    for ip, mac in conn.execute("SELECT ip, mac FROM devices WHERE mac IS NOT NULL ORDER BY ip"):
        if ip and _TPLINK.search(vendor_of(_mac(mac)) or "") and ip not in out:
            out.append(ip)
    return out
