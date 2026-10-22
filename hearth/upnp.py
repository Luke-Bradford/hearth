"""Read the router's UPnP Internet Gateway Device (IGD): whole-home internet traffic, the link's
state and rates, and the public IP. Many routers offer it with nothing to set up; many have it
switched off (a safe default) - then Hearth simply doesn't use it.

Read-only and pinned to the router:
- Only answers from the default gateway's address count, and every URL Hearth then requests -
  the device description and the SOAP control URLs - must resolve to http://<gateway IP>
  (any port). A UDP answer can be spoofed on the LAN, so a description pointing anywhere else
  (another host, a name, loopback, https) makes that service unusable: Hearth never sends a
  request off the router.
- No redirects (http.client doesn't follow them), a 5 s timeout and a 64 KB cap on every reply.
- Replies must be strict UTF-8, and any DTD or entity declaration is refused before parsing -
  checked after decoding, so no encoding trick (UTF-16, a declared other charset) gets one past.
- Only the actions in ALLOWED_ACTIONS are ever sent: reads. Never a port mapping or a Set*.
UPnP has no authentication, so its figures are "what the router says", shown as such."""
import http.client
import ipaddress
import re
import socket
import time
import urllib.parse
import xml.etree.ElementTree as ET

IGD_TYPES = ("urn:schemas-upnp-org:device:InternetGatewayDevice:1",
             "urn:schemas-upnp-org:device:InternetGatewayDevice:2")
SSDP = ("239.255.255.250", 1900)
TIMEOUT_S = 5
MAX_REPLY = 64 * 1024
COUNTER_WRAP = 2 ** 32       # the IGD byte counters are 32-bit on many routers
WAN_COMMON = "WANCommonInterfaceConfig"
WAN_CONNECTIONS = ("WANIPConnection", "WANPPPConnection")
ALLOWED_ACTIONS = frozenset({"GetTotalBytesReceived", "GetTotalBytesSent", "GetCommonLinkProperties",
                             "GetExternalIPAddress", "GetStatusInfo"})


class UpnpError(Exception):
    """Why the gateway couldn't be read. Never carries anything secret (UPnP has nothing)."""


# ----------------------------------------------------------------------------- pinning & parsing
def pinned(url, gateway, base=None):
    """`url` (resolved against `base`) if it is http:// on the gateway's own IP address, else
    UpnpError. The gateway is an IP literal; a host name never matches, so DNS can't redirect."""
    full = urllib.parse.urljoin(base, url) if base else url
    p = urllib.parse.urlsplit(full)
    try:
        host_ok = p.hostname is not None and ipaddress.ip_address(p.hostname) == ipaddress.ip_address(gateway)
        p.port                   # raises ValueError for a malformed or out-of-range port
    except ValueError:
        host_ok = False
    if p.scheme != "http" or not host_ok:
        raise UpnpError(f"the router's UPnP description points away from the router ({p.scheme}://{p.hostname}) - not used")
    return full


_DECL = re.compile(r"""^\s*<\?xml[^>]*?\bencoding\s*=\s*["']([^"']+)["']""", re.I)
_DTD = re.compile(r"<!\s*(DOCTYPE|ENTITY)", re.I)


def parse_xml(raw):
    """Strict UTF-8 XML with no DTD or entity declaration, or UpnpError."""
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff") or raw[:4] in (b"\x00\x00\xfe\xff", b"\xff\xfe\x00\x00") or b"\x00" in raw:
        raise UpnpError("the router's UPnP reply isn't UTF-8")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise UpnpError("the router's UPnP reply isn't UTF-8") from None
    m = _DECL.match(text)
    if m and m.group(1).strip().lower() not in ("utf-8", "utf8"):
        raise UpnpError("the router's UPnP reply declares an encoding other than UTF-8")
    if _DTD.search(text):
        raise UpnpError("the router's UPnP reply carries a DTD - refused")
    try:
        return ET.fromstring(text)
    except ET.ParseError:
        raise UpnpError("the router's UPnP reply isn't valid XML") from None


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def services(root, desc_url, gateway):
    """{service name: (service type, control URL)} for the WAN services the description lists,
    each control URL pinned to the gateway. A service pointing elsewhere is left out; if that
    leaves nothing usable, the reason is raised."""
    base = desc_url
    for el in root.iter():
        if _local(el.tag) == "URLBase" and (el.text or "").strip():
            base = el.text.strip()
    out, refused = {}, None
    for svc in (el for el in root.iter() if _local(el.tag) == "service"):
        fields = {_local(c.tag): (c.text or "").strip() for c in svc}
        stype, ctrl = fields.get("serviceType", ""), fields.get("controlURL", "")
        name = stype.split(":")[-2] if stype.count(":") >= 2 else ""
        if name not in (WAN_COMMON, *WAN_CONNECTIONS) or not ctrl or name in out:
            continue
        try:
            pinned(base, gateway)                 # the base too: a relative control URL inherits it
            out[name] = (stype, pinned(ctrl, gateway, base))
        except UpnpError as e:
            refused = e
    if not out and refused:
        raise refused
    return out


# ----------------------------------------------------------------------------- HTTP
def http_get(url, gateway, body=None, headers=None):
    """GET (or POST with a body) to a pinned URL; the reply body, capped. No redirects."""
    url = pinned(url, gateway)
    p = urllib.parse.urlsplit(url)
    conn = http.client.HTTPConnection(p.hostname, p.port or 80, timeout=TIMEOUT_S)
    try:
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
        # a whole-request deadline: read1 returns whatever has arrived (each wait still bounded by
        # the connection's TIMEOUT_S), so a router trickling bytes is cut off within ~2 x TIMEOUT_S
        deadline = time.monotonic() + TIMEOUT_S
        conn.request("POST" if body is not None else "GET", path, body=body, headers=headers or {})
        r = conn.getresponse()
        status, raw = r.status, b""
        while len(raw) <= MAX_REPLY:
            if time.monotonic() > deadline:
                raise UpnpError("the router's UPnP reply took too long")
            chunk = r.read1(MAX_REPLY + 1 - len(raw))
            if not chunk:
                break
            raw += chunk
    except (OSError, http.client.HTTPException) as e:
        raise UpnpError(f"the router didn't answer UPnP ({type(e).__name__})") from None
    finally:
        conn.close()
    if len(raw) > MAX_REPLY:
        raise UpnpError("the router's UPnP reply is too large")
    if status != 200:
        raise UpnpError(f"the router answered UPnP with HTTP {status}")
    return raw


def soap(control_url, service_type, action, gateway, getter=http_get):
    """One read action; {output argument: text}. Only ALLOWED_ACTIONS are sent."""
    if action not in ALLOWED_ACTIONS:
        raise UpnpError(f"{action} isn't an allowed UPnP read")
    body = ('<?xml version="1.0" encoding="utf-8"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:{action} xmlns:u="{service_type}"/></s:Body></s:Envelope>').encode()
    raw = getter(control_url, gateway, body, {"Content-Type": 'text/xml; charset="utf-8"',
                                             "SOAPAction": f'"{service_type}#{action}"'})
    root = parse_xml(raw)
    resp = next((el for el in root.iter() if _local(el.tag) == f"{action}Response"), None)
    if resp is None:
        raise UpnpError(f"the router gave no answer to {action}")
    return {_local(c.tag): (c.text or "").strip() for c in resp}


# ----------------------------------------------------------------------------- discovery
def local_address_towards(gateway):
    """This computer's address on the interface that routes to the gateway, or None. No packet
    is sent: connecting a UDP socket only picks the route."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect((gateway, SSDP[1]))
            return probe.getsockname()[0]
    except OSError:
        return None


def discover(gateway, timeout=3.0, sock=None):
    """The gateway's device-description URL from an SSDP search, or None if it didn't answer
    within `timeout` seconds in all. Answers from any other address are ignored, and can't keep
    the search going: the deadline is for the whole search. The search leaves through the
    interface that routes to the gateway, not whichever the system picks (Docker, VPNs)."""
    s = sock or socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    deadline = time.monotonic() + timeout
    try:
        if sock is None:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            local = local_address_towards(gateway)
            if local:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local))
        for st in IGD_TYPES:
            s.sendto((f'M-SEARCH * HTTP/1.1\r\nHOST: {SSDP[0]}:{SSDP[1]}\r\nMAN: "ssdp:discover"\r\n'
                      f"MX: 2\r\nST: {st}\r\n\r\n").encode(), SSDP)
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            s.settimeout(left)
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                return None
            except OSError:
                continue   # e.g. a stray ICMP "port unreachable" (Windows): keep listening until the deadline
            if addr[0] != gateway:
                continue
            for line in data.decode("latin-1").split("\r\n"):
                key, _, value = line.partition(":")
                if key.strip().upper() == "LOCATION":
                    try:
                        return pinned(value.strip(), gateway)
                    except UpnpError:
                        return None
    finally:
        if sock is None:
            s.close()


# ----------------------------------------------------------------------------- reading
def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


class Gateway:
    """The router's WAN services, found once and then read every minute."""

    def __init__(self, gateway, desc_url, getter=http_get):
        self.gateway, self.getter = gateway, getter
        self.services = services(parse_xml(getter(desc_url, gateway)), desc_url, gateway)
        if WAN_COMMON not in self.services:
            raise UpnpError("the router's UPnP doesn't offer its traffic counters")

    def _call(self, name, action):
        stype, url = self.services[name]
        return soap(url, stype, action, self.gateway, self.getter)

    def _optional(self, name, action):
        """An action not every router implements: a fault (HTTP 500) or a missing answer is {}."""
        try:
            return self._call(name, action)
        except UpnpError:
            return {}

    def read(self):
        """{rx_total, tx_total, link_up, down_bps, up_bps, public_ip, connected, uptime_s}.
        Only the two byte counters are required; routers implement different subsets of the
        rest, so a value a router can't give is None rather than failing the whole read."""
        rx = _int(self._call(WAN_COMMON, "GetTotalBytesReceived").get("NewTotalBytesReceived"))
        tx = _int(self._call(WAN_COMMON, "GetTotalBytesSent").get("NewTotalBytesSent"))
        if rx is None or tx is None:
            raise UpnpError("the router's UPnP traffic counters are unreadable")
        link = self._optional(WAN_COMMON, "GetCommonLinkProperties")
        out = {"rx_total": rx, "tx_total": tx,
               "link_up": (link.get("NewPhysicalLinkStatus") or "").lower() == "up" if link else None,
               "down_bps": _int(link.get("NewLayer1DownstreamMaxBitRate")),
               "up_bps": _int(link.get("NewLayer1UpstreamMaxBitRate")),
               "public_ip": None, "connected": None, "uptime_s": None}
        conn = next((n for n in WAN_CONNECTIONS if n in self.services), None)
        if conn:
            out["public_ip"] = public_ip(self._optional(conn, "GetExternalIPAddress").get("NewExternalIPAddress"))
            st = self._optional(conn, "GetStatusInfo")
            out["connected"] = (st.get("NewConnectionStatus") or "").lower() == "connected" if st else None
            out["uptime_s"] = _int(st.get("NewUptime"))
        return out


def public_ip(text):
    """A real public address, or None. Routers report 0.0.0.0 - or a private or carrier-grade NAT
    address - while the line is down or behind another router: that isn't a public IP, and must
    never look like the address changed."""
    try:
        ip = ipaddress.ip_address((text or "").strip())
    except ValueError:
        return None
    return str(ip) if ip.is_global else None


def counter_delta(prev, cur, dur_s, link_bps):
    """Bytes moved between two readings of a counter, or None. A decrease is a 32-bit wrap when
    the implied rate is plausible for the link (or 1 Gb/s if unknown), else a router restart
    (that interval is dropped). A restart can't always be told apart: if the counter restarted
    from zero and has already passed the old value within one interval, it reads as an ordinary
    increase and books too much. Cumulative counters can't show this; it needs a restart and
    that much traffic within one reading, so it's left."""
    if prev is None or cur is None or dur_s <= 0:
        return None
    if cur >= prev:
        return cur - prev
    wrapped = cur + COUNTER_WRAP - prev
    limit = (link_bps or 10 ** 9) * 1.1 / 8 * dur_s
    return wrapped if prev < COUNTER_WRAP and wrapped <= limit else None
