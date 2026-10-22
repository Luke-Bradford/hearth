"""Learn devices' own names. Many devices announce a friendly name on the LAN, the same way
a phone finds a TV to cast to:

- mDNS / Bonjour (UDP 5353): Apple devices, Chromecast / Android TV ("SHIELD"), Hue bridges,
  printers, speakers. We ask for common service types with the unicast-response bit set,
  so replies come straight back to our socket and we never bind port 5353.
- UPnP / SSDP (UDP 1900): TVs, media servers, consoles, routers. Each reply points at a
  small XML description holding friendlyName / manufacturer / modelName.

Read-only and light: a handful of multicast packets per run. Everything learned here is
untrusted display text (escaped by the dashboard, never interpreted).
"""
import ipaddress
import re
import select
import socket
import struct
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FuturesTimeout
from urllib.parse import urlparse

from .ids import looks_like_id

MDNS_ADDR = ("224.0.0.251", 5353)
SSDP_ADDR = ("239.255.255.250", 1900)
MDNS_SERVICES = (
    "_googlecast._tcp.local", "_airplay._tcp.local", "_raop._tcp.local", "_companion-link._tcp.local",
    "_hap._tcp.local", "_hue._tcp.local", "_device-info._tcp.local", "_spotify-connect._tcp.local",
    "_ipp._tcp.local", "_printer._tcp.local", "_smb._tcp.local", "_androidtvremote2._tcp.local",
    "_sonos._tcp.local", "_home-assistant._tcp.local", "_workstation._tcp.local", "_http._tcp.local",
)
_MAX_DESC_BYTES = 64 * 1024
_MAX_SSDP_DEVICES = 64       # description fetches per run
_SSDP_DEADLINE_S = 6.0       # total time allowed for all of them
_MAX_RECV_ERRORS = 20        # socket errors tolerated while collecting SSDP replies
_FETCH_TOTAL_S = 4.0         # total time for any one fetch (connect + read)
_MAX_RECORDS_PER_IP = 200    # mDNS records kept per device per run (a chatty host can't grow memory)

T_A, T_PTR, T_TXT, T_SRV = 1, 12, 16, 33

# services whose instance name is the device's own name; others (Spotify, web servers,
# Home Assistant's instance) name an app running on it, so they're never used as its name
DEVICE_NAMING_SERVICES = ("._googlecast.", "._airplay.", "._raop.", "._companion-link.", "._hap.",
                          "._hue.", "._device-info.", "._androidtvremote2.", "._sonos.", "._ipp.",
                          "._printer.")


# --------------------------------------------------------------------------- DNS wire format
def build_query(names, qtype=T_PTR):
    """One mDNS query packet asking for every name, unicast-response bit set (RFC 6762 5.4)."""
    out = struct.pack("!HHHHHH", 0, 0, len(names), 0, 0, 0)
    for name in names:
        out += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p) + b"\0"
        out += struct.pack("!HH", qtype, 0x8001)
    return out


def _read_name(buf, off, depth=0):
    labels = []
    while True:
        if off >= len(buf) or depth > 20:
            raise ValueError("bad name")
        n = buf[off]
        if n & 0xC0 == 0xC0:  # compression pointer
            ptr = struct.unpack("!H", buf[off:off + 2])[0] & 0x3FFF
            rest, _ = _read_name(buf, ptr, depth + 1)
            labels.append(rest)
            return ".".join(x for x in labels if x), off + 2
        off += 1
        if n == 0:
            return ".".join(labels), off
        labels.append(buf[off:off + n].decode("utf-8", "replace"))
        off += n


def parse_records(buf):
    """[(name, type, data)] for every answer/authority/additional record in a DNS packet.
    data: str for PTR/A, dict for TXT, (port, target) for SRV."""
    if len(buf) < 12:
        return []
    _, _, qd, an, ns, ar = struct.unpack("!HHHHHH", buf[:12])
    off, out = 12, []
    for _ in range(qd):
        _, off = _read_name(buf, off)
        off += 4
    for _ in range(an + ns + ar):
        name, off = _read_name(buf, off)
        rtype, _, _, rdlen = struct.unpack("!HHIH", buf[off:off + 10])
        off += 10
        rdata, start = buf[off:off + rdlen], off
        off += rdlen
        if rtype == T_PTR:
            data, _ = _read_name(buf, start)
        elif rtype == T_A and rdlen == 4:
            data = socket.inet_ntoa(rdata)
        elif rtype == T_SRV and rdlen >= 6:
            port = struct.unpack("!H", rdata[4:6])[0]
            data = (port, _read_name(buf, start + 6)[0])
        elif rtype == T_TXT:
            data, i = {}, 0
            while i < len(rdata):
                ln = rdata[i]
                item = rdata[i + 1:i + 1 + ln].decode("utf-8", "replace")
                i += 1 + ln
                k, _, v = item.partition("=")
                if k:
                    data[k.lower()] = v
        else:
            continue
        out.append((name, rtype, data))
    return out


def _instance_label(instance):
    """'Hue Bridge - 1A2B3C._hue._tcp.local' -> 'Hue Bridge - 1A2B3C'; strips RAOP's 'MAC@' prefix."""
    label = instance.split("._", 1)[0]
    return label.split("@", 1)[1] if re.match(r"^[0-9A-F]{12}@", label) else label


def summarise_mdns(records):
    """Best friendly name and model from one device's mDNS records. Priority, whatever order
    the records arrive in: the name the user gave it (TXT fn=, e.g. Cast devices) > a service
    instance name > its .local hostname."""
    given = instance = model = host = None
    for name, rtype, data in records:
        if rtype == T_TXT:
            if any(s in name for s in DEVICE_NAMING_SERVICES):
                given = given or data.get("fn")
            model = model or data.get("md") or data.get("am") or data.get("model") or data.get("ty")
        elif rtype == T_PTR and not data.startswith("_") and any(s in data for s in DEVICE_NAMING_SERVICES):
            instance = instance or _instance_label(data)
        elif rtype == T_A and name.endswith(".local"):
            host = host or name[:-len(".local")]
    if host and looks_like_id(host):
        host = None  # e.g. a UUID hostname: the reverse-DNS name will be more useful
    return {"friendly": _clip(given or instance or host), "model": _clip(model)}


def _clip(text, limit=80):
    """Announced strings come from any device on the LAN: keep them display-sized."""
    return re.sub(r"\s+", " ", text).strip()[:limit] if text else text


def mdns_scan(local_ip, timeout=3.0):
    """{ip: {"friendly": str|None, "model": str|None}} for devices answering mDNS."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
        s.bind((local_ip, 0))
        for i in range(0, len(MDNS_SERVICES), 6):  # several small packets, well under any MTU
            s.sendto(build_query(MDNS_SERVICES[i:i + 6]), MDNS_ADDR)
        per_ip, end = {}, time.time() + timeout
        while time.time() < end:
            ready, _, _ = select.select([s], [], [], 0.25)
            if not ready:
                continue
            try:
                data, addr = s.recvfrom(9000)
            except OSError:  # e.g. Windows reports an ICMP "port unreachable" here: keep going
                continue
            recs = per_ip.setdefault(addr[0], [])
            if len(recs) >= _MAX_RECORDS_PER_IP:
                continue
            try:
                recs.extend(parse_records(data)[:_MAX_RECORDS_PER_IP - len(recs)])
            except (ValueError, struct.error, IndexError):
                continue  # malformed packet: ignore
        return {ip: summarise_mdns(recs) for ip, recs in per_ip.items()}
    finally:
        s.close()


# --------------------------------------------------------------------------- SSDP / UPnP
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A device's description URL must be served by that device: following a redirect would
    let anything on the LAN make us fetch an arbitrary address."""

    def redirect_request(self, *args, **kwargs):
        return None


# no proxy: a system http_proxy would send LAN fetches elsewhere and break the same-IP rule
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def _fetchable(url, ip):
    """Plain http on the very IP that answered, which must be an ordinary private LAN address."""
    u = urlparse(url)
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (u.scheme == "http" and u.hostname == ip and a.is_private
            and not a.is_loopback and not a.is_link_local)


def fetch_description(url, total_s=None):
    """UPnP description fields, or None. Caller has already checked the URL with _fetchable."""
    total = total_s if total_s is not None else _FETCH_TOTAL_S
    deadline = time.monotonic() + total
    try:
        # the socket timeout applies per blocking socket operation (connect, then each read of
        # the reply's headers): about half the total each, at least 0.5 s. That bounds a slow
        # device without being exact - a header trickled in many small reads can still run past
        # the total; the body below is checked against the deadline, and the caller's overall
        # deadline (_SSDP_DEADLINE_S) stops waiting for stragglers either way
        with _opener.open(url, timeout=max(0.5, min(3.0, total / 2))) as r:  # redirects refused
            if r.status != 200:
                return None
            # read1 returns after at most one network read, so the total deadline is checked
            # between small reads; read(n) would block until n bytes arrived, letting a device
            # that trickles one byte at a time hold this thread for hours
            chunks, size = [], 0
            while size < _MAX_DESC_BYTES:
                if time.monotonic() > deadline:
                    return None  # too slow: give up on this device
                chunk = r.read1(min(4096, _MAX_DESC_BYTES - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            xml = b"".join(chunks).decode("utf-8", "replace")
    except Exception:
        return None
    return {"friendly": _xml_field(xml, "friendlyName"), "manufacturer": _xml_field(xml, "manufacturer"),
            "model": _xml_field(xml, "modelName")}


def _xml_field(xml, tag):
    m = re.search(rf"<{tag}>\s*(.*?)\s*</{tag}>", xml, re.S | re.I)
    return re.sub(r"\s+", " ", m.group(1)).strip()[:80] if m else None


def ssdp_scan(local_ip, timeout=3.0):
    """{ip: {"friendly", "manufacturer", "model"}} from UPnP device descriptions. Description
    URLs are only fetched from the same private IP that answered, and redirects are refused."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    locations = {}
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
        s.bind((local_ip, 0))
        msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
               "MX: 2\r\nST: upnp:rootdevice\r\n\r\n").encode()
        s.sendto(msg, SSDP_ADDR)
        end, errors = time.time() + timeout, 0
        while time.time() < end:
            ready, _, _ = select.select([s], [], [], 0.25)
            if not ready:
                continue
            try:
                data, addr = s.recvfrom(4096)
            except OSError:  # e.g. Windows reports an ICMP "port unreachable" here: keep what we have
                errors += 1
                if errors >= _MAX_RECV_ERRORS:
                    break  # the socket keeps failing: stop rather than spin until the deadline
                continue
            m = re.search(rb"(?im)^location:\s*(\S+)", data)
            if m:
                locations.setdefault(addr[0], m.group(1).decode("ascii", "replace"))
    finally:
        s.close()

    def fetch(item):
        return item[0], fetch_description(item[1])

    # in parallel, with an overall deadline: devices that hang can't stall the sweep
    todo = [(ip, url) for ip, url in list(locations.items())[:_MAX_SSDP_DEVICES] if _fetchable(url, ip)]
    out = {}
    if not todo:
        return out
    ex = ThreadPoolExecutor(max_workers=8, thread_name_prefix="ssdp")
    try:
        for fut in as_completed([ex.submit(fetch, item) for item in todo], timeout=_SSDP_DEADLINE_S):
            ip, info = fut.result()
            if info:
                out[ip] = info
    except FuturesTimeout:
        pass  # keep what arrived in time; stragglers finish in the background (3 s socket timeout)
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return out


def identify(local_ip):
    """Merged {ip: {"friendly", "app_name", "model"}}. friendly is the mDNS name - the machine's
    own (a Mac's computer name, a Cast device's given name). app_name is the UPnP friendlyName,
    kept apart: any program can announce a UPnP device, so it may name an app (an antivirus
    agent, a media server) rather than the machine."""
    result = {}
    try:  # each protocol on its own: one failing (e.g. a socket error) mustn't skip the other
        upnp = ssdp_scan(local_ip)
    except OSError:
        upnp = {}
    try:
        mdns = mdns_scan(local_ip)
    except OSError:
        mdns = {}
    for ip, info in upnp.items():
        result[ip] = {"friendly": None, "app_name": info["friendly"],
                      "model": " ".join(x for x in (info["manufacturer"], info["model"]) if x) or None}
    for ip, info in mdns.items():
        cur = result.setdefault(ip, {"friendly": None, "app_name": None, "model": None})
        cur["friendly"] = info["friendly"] or cur["friendly"]
        cur["model"] = cur["model"] or info["model"]
    return result
