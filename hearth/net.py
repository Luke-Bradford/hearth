"""Low-level network probes: ping (with optional TTL), gateway/subnet detection,
traceroute, ARP table, reverse DNS and MAC vendor lookup. Windows and Linux."""
import csv
import ipaddress
import os
import platform
import re
import select
import socket
import struct
import subprocess
import threading
import time
import urllib.request

from .config import IS_WIN, OUI_PATH, log

# ICMP status codes from IcmpSendEcho (ipexport.h)
_IP_SUCCESS = 0
_IP_TTL_EXPIRED_TRANSIT = 11013

if IS_WIN:
    import ctypes
    import ctypes.wintypes as wt

    class _IPOpt(ctypes.Structure):
        _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte),
                    ("Flags", ctypes.c_ubyte), ("OptionsSize", ctypes.c_ubyte),
                    ("OptionsData", ctypes.c_void_p)]

    class _EchoReply(ctypes.Structure):
        _fields_ = [("Address", wt.ULONG), ("Status", wt.ULONG),
                    ("RoundTripTime", wt.ULONG), ("DataSize", wt.USHORT),
                    ("Reserved", wt.USHORT), ("Data", ctypes.c_void_p),
                    ("Options", _IPOpt)]

    _ip = ctypes.windll.iphlpapi
    _ip.IcmpCreateFile.restype = wt.HANDLE
    _ip.IcmpCloseHandle.argtypes = [wt.HANDLE]
    _ip.IcmpSendEcho.argtypes = [wt.HANDLE, wt.ULONG, ctypes.c_void_p, wt.WORD,
                                 ctypes.c_void_p, ctypes.c_void_p, wt.DWORD, wt.DWORD]
    _ip.IcmpSendEcho.restype = wt.DWORD
    _PAYLOAD = b"hearth-probe-32-bytes-padding!!!"

    class Pinger:
        """Uses the Windows ICMP API, so no Administrator rights are needed."""
        def __init__(self):
            self.h = _ip.IcmpCreateFile()
            self.buf = ctypes.create_string_buffer(ctypes.sizeof(_EchoReply) + len(_PAYLOAD) + 64)

        def _send(self, ip, timeout_ms, ttl=None):
            addr = struct.unpack("<I", socket.inet_aton(ip))[0]
            opt = ctypes.byref(_IPOpt(Ttl=ttl)) if ttl else None
            t0 = time.perf_counter()
            n = _ip.IcmpSendEcho(self.h, addr, _PAYLOAD, len(_PAYLOAD), opt,
                                 self.buf, len(self.buf), timeout_ms)
            dt = (time.perf_counter() - t0) * 1000.0
            if n == 0:
                return None, None, dt
            rep = _EchoReply.from_buffer(self.buf)
            return rep.Status, socket.inet_ntoa(struct.pack("<I", rep.Address)), dt

        def ping(self, ip, timeout_ms):
            status, _, dt = self._send(ip, timeout_ms)
            # wall-clock timing gives sub-ms resolution; the API only reports whole ms
            return round(dt, 2) if status == _IP_SUCCESS else None

        def hop(self, ip, ttl, timeout_ms):
            """(address that answered, rtt) for a TTL-limited probe, or (None, None)."""
            status, addr, dt = self._send(ip, timeout_ms, ttl)
            if status in (_IP_SUCCESS, _IP_TTL_EXPIRED_TRANSIT):
                return addr, round(dt, 2)
            return None, None

        def close(self):
            _ip.IcmpCloseHandle(self.h)
else:
    _TIME_RE = re.compile(r"time[=<]([\d.]+)")
    _FROM_RE = re.compile(r"[Ff]rom ([\d.]+)")

    class _ProcessPinger:
        """Uses the system ping binary (setuid or ping_group_range), so no root is needed. The
        fallback where ICMP sockets aren't allowed (and on macOS): one process per probe."""
        def _run(self, args, timeout_ms):
            try:
                return subprocess.run(args, capture_output=True, text=True,
                                      timeout=timeout_ms / 1000 + 2).stdout
            except Exception:
                return ""

        def ping(self, ip, timeout_ms):
            w = str(max(1, round(timeout_ms / 1000)))
            if platform.system() == "Darwin":
                w = str(timeout_ms)
            m = _TIME_RE.search(self._run(["ping", "-n", "-c", "1", "-W", w, ip], timeout_ms))
            return round(float(m.group(1)), 2) if m else None

        def hop(self, ip, ttl, timeout_ms):
            w = str(max(1, round(timeout_ms / 1000)))
            # the TTL flag differs: Linux iputils uses -t, macOS uses -m (-t is a timeout there)
            ttl_flag = "-m" if platform.system() == "Darwin" else "-t"
            t0 = time.perf_counter()
            out = self._run(["ping", "-n", "-c", "1", "-W", w, ttl_flag, str(ttl), ip], timeout_ms)
            dt = round((time.perf_counter() - t0) * 1000.0, 2)
            m = _FROM_RE.search(out)
            if m:
                return m.group(1), dt
            m = _TIME_RE.search(out)
            return (ip, round(float(m.group(1)), 2)) if m else (None, None)

        def close(self):
            pass

    class _SocketPinger:
        """Linux "ping sockets" (SOCK_DGRAM + IPPROTO_ICMP): ICMP from this process, no root and
        no ping process per probe. Allowed when net.ipv4.ping_group_range covers our group (the
        default on most distributions, and inside Docker containers). The kernel fills in the
        echo identifier and checksum and delivers only this socket's replies. "Time exceeded"
        from a router on the way (traceroute) arrives on the socket's error queue (IP_RECVERR),
        which also says which router sent it."""

        def __init__(self):
            self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
            try:
                self.s.setsockopt(socket.SOL_IP, _IP_RECVERR, 1)
                self.s.setblocking(False)
            except OSError:
                self.s.close()
                raise
            self.seq = int.from_bytes(os.urandom(2), "big")
            # poll, not select: select() can't watch a descriptor numbered 1024 or more, which a
            # long-running server with many open files can reach
            self.poller = select.poll()
            self.poller.register(self.s, select.POLLIN | select.POLLERR)
            # one probe at a time per socket: the sequence number and the drain are per socket, so
            # a pinger shared between threads would mix up replies (callers use one per thread)
            self.lock = threading.Lock()

        def _probe(self, ip, timeout_ms, ttl=None):
            """("reply", ip, ms), ("hop", router, ms) or (None, None, None)."""
            with self.lock:
                return self._probe_locked(ip, timeout_ms, ttl)

        def _probe_locked(self, ip, timeout_ms, ttl):
            self._drain()
            self.seq = (self.seq + 1) & 0xFFFF
            seq = self.seq
            try:
                self.s.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl or 64)
                t0 = time.perf_counter()
                self.s.sendto(build_echo(seq), (ip, 0))
            except OSError:
                return None, None, None
            deadline = t0 + timeout_ms / 1000.0
            errors = 0  # socket errors in a row: a socket that keeps failing mustn't spin until the deadline
            while True:
                if errors >= 10:
                    return None, None, None
                left = deadline - time.perf_counter()
                if left <= 0:
                    return None, None, None
                if not self.poller.poll(left * 1000.0):
                    continue  # nothing yet: the loop checks the deadline
                dt = (time.perf_counter() - t0) * 1000.0
                try:  # an ICMP error about one of our probes (time exceeded on the way, unreachable)
                    data, anc, _, _ = self.s.recvmsg(512, 512, _MSG_ERRQUEUE)
                    err = next((parse_recverr(d) for lvl, typ, d in anc
                                if lvl == socket.SOL_IP and typ == _IP_RECVERR), None)
                    if err and echo_seq(data) == seq and err[0] == _SO_EE_ORIGIN_ICMP:
                        if err[1] == _ICMP_TIME_EXCEEDED and err[3]:
                            return "hop", err[3], dt
                        return None, None, None  # unreachable or similar: no answer from the target
                    continue
                except (BlockingIOError, InterruptedError):
                    pass
                except OSError:
                    errors += 1
                    continue
                try:
                    data = self.s.recv(512)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:  # an error was pending (read above next time round)
                    errors += 1
                    continue
                errors = 0
                if is_echo_reply(data, seq):
                    return "reply", ip, dt

        def _drain(self):
            """Throw away late replies and errors from earlier probes."""
            for flags in (_MSG_ERRQUEUE, 0):
                for _ in range(64):
                    try:
                        self.s.recvmsg(512, 512, flags)
                    except OSError:  # nothing left (or only errors, read off the other queue)
                        break

        def ping(self, ip, timeout_ms):
            kind, _, dt = self._probe(ip, timeout_ms)
            return round(dt, 2) if kind == "reply" else None

        def hop(self, ip, ttl, timeout_ms):
            """(address that answered, rtt) for a TTL-limited probe, or (None, None)."""
            kind, addr, dt = self._probe(ip, timeout_ms, ttl)
            return (addr, round(dt, 2)) if kind else (None, None)

        def close(self):
            self.s.close()

    _pinger_kind, _pinger_kind_lock = [], threading.Lock()  # which one this process uses, logged once
    _socket_errors_logged = set()  # errnos of other socket failures, each logged once

    def _note_kind(kind, message):
        with _pinger_kind_lock:
            if not _pinger_kind:
                _pinger_kind.append(kind)
                log(message)

    def Pinger():
        """A ping socket where the system allows them (Linux), else the ping binary."""
        if platform.system() == "Linux":
            try:
                p = _SocketPinger()
                _note_kind("socket", "ping: using ICMP sockets")
                return p
            except PermissionError:  # ping_group_range doesn't cover our group
                _note_kind("process", "ping: ICMP sockets not allowed here - using the ping program "
                                      "(allow them with: sysctl net.ipv4.ping_group_range='0 2147483647')")
            except OSError as e:  # anything else (e.g. out of file descriptors): say what, not the sysctl hint
                with _pinger_kind_lock:
                    first = e.errno not in _socket_errors_logged
                    _socket_errors_logged.add(e.errno)
                if first:  # once per kind of error: a lasting one would otherwise log on every probe
                    log(f"ping: can't open an ICMP socket ({e.strerror or e}) - using the ping program meanwhile")
        return _ProcessPinger()


# --------------------------------------------------------------------------- ICMP socket helpers
# (pure functions, so they're tested on every platform)
_ICMP_ECHO_REQUEST, _ICMP_ECHO_REPLY, _ICMP_TIME_EXCEEDED = 8, 0, 11
_SO_EE_ORIGIN_ICMP = 2
_IP_RECVERR = getattr(socket, "IP_RECVERR", 11)           # Linux values, for older Pythons
_MSG_ERRQUEUE = getattr(socket, "MSG_ERRQUEUE", 0x2000)
_ECHO_PAYLOAD = b"hearth-probe-32-bytes-padding!!!"


def build_echo(seq, payload=_ECHO_PAYLOAD):
    """An ICMP echo request for a ping socket: the kernel fills in the identifier and checksum."""
    return struct.pack("!BBHHH", _ICMP_ECHO_REQUEST, 0, 0, 0, seq & 0xFFFF) + payload


def echo_seq(packet):
    """The sequence number of an ICMP echo packet (no IP header, as ping sockets deliver it)."""
    return struct.unpack("!H", packet[6:8])[0] if len(packet) >= 8 else None


def is_echo_reply(packet, seq):
    return len(packet) >= 8 and packet[0] == _ICMP_ECHO_REPLY and echo_seq(packet) == seq


def parse_recverr(data):
    """(origin, icmp type, icmp code, router address or None) from an IP_RECVERR message:
    struct sock_extended_err (errno, origin, type, code, pad, info, data), then the sockaddr_in
    of the router that sent the ICMP error."""
    if len(data) < 16:
        return None
    _, origin, icmp_type, code, _, _, _ = struct.unpack("=IBBBBII", data[:16])
    addr = None
    if len(data) >= 24 and struct.unpack("=H", data[16:18])[0] == socket.AF_INET:
        addr = socket.inet_ntoa(data[20:24])
    return origin, icmp_type, code, addr


# --------------------------------------------------------------------------- local network
def local_ip(probe="1.1.1.1"):
    """The address this machine uses to reach the internet (picks the right NIC on multi-NIC hosts)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((probe, 53))  # UDP connect sends nothing; it just selects the route
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def default_gateway():
    """IPv4 default gateway for the interface that reaches the internet."""
    me = local_ip()
    if IS_WIN:
        try:
            out = subprocess.run(["route", "print", "-4", "0.0.0.0"], capture_output=True,
                                 text=True, timeout=10).stdout
        except Exception:
            return None
        best = None
        for gw, iface, metric in re.findall(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+([\d.]+)\s+([\d.]+)\s+(\d+)", out, re.M):
            score = (iface != me, int(metric))  # prefer the internet-facing NIC, then lowest metric
            if best is None or score < best[0]:
                best = (score, gw)
        return best[1] if best else None
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                p = line.split()
                if p[1] == "00000000" and int(p[3], 16) & 2:  # destination 0/0, RTF_GATEWAY
                    return socket.inet_ntoa(struct.pack("<I", int(p[2], 16)))
    except OSError:
        pass
    return None


def local_network():
    """ipaddress.IPv4Network of this machine's LAN (falls back to /24)."""
    me = local_ip()
    if not me:
        return None
    me = str(ipaddress.IPv4Address(me))  # validated before it goes into a command line
    prefix = None
    try:
        if IS_WIN:
            # ask for the prefix length of exactly this address: no ipconfig text to parse, so
            # no partial-address matches and no dependence on the Windows display language
            out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                                  f"(Get-NetIPAddress -IPAddress '{me}' -ErrorAction Stop).PrefixLength"],
                                 capture_output=True, text=True, timeout=20).stdout.strip()
        else:
            out = subprocess.run(["ip", "-4", "-o", "addr"], capture_output=True, text=True, timeout=10).stdout
            m = re.search(r"\binet " + re.escape(me) + r"/(\d+)", out)
            out = m.group(1) if m else ""
        prefix = int(out) if out.isdigit() and 8 <= int(out) <= 32 else None
    except Exception:
        pass
    if prefix is None:
        log(f"couldn't read the netmask for {me}; assuming /24 (set discovery_subnet to override)")
    return ipaddress.ip_network(f"{me}/{prefix or 24}", strict=False)


def scan_hosts(net, cap=1022):
    """Host addresses to sweep; big networks are clipped to the /22 around this machine."""
    if net.num_addresses - 2 > cap:
        net = ipaddress.ip_network(f"{local_ip()}/22", strict=False)
    return [str(h) for h in net.hosts()]


def traceroute(dest, max_hops=12, timeout_ms=1000):
    """[(ttl, ip|None, rtt|None)] up to and including the destination."""
    p, hops = Pinger(), []
    try:
        for ttl in range(1, max_hops + 1):
            addr, rtt = p.hop(dest, ttl, timeout_ms)
            hops.append((ttl, addr, rtt))
            if addr == dest:
                break
    finally:
        p.close()
    return hops


_ARP_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+.*?([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})")


def read_arp():
    """{ip: mac} from the OS neighbour table."""
    try:
        if IS_WIN:
            out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=15).stdout
        else:
            out = subprocess.run(["ip", "neigh"], capture_output=True, text=True, timeout=15).stdout
    except Exception:
        return {}
    res = {}
    for ip, mac in _ARP_RE.findall(out):
        mac = mac.replace("-", ":").lower()
        if mac != "ff:ff:ff:ff:ff:ff" and not mac.startswith("01:00:5e"):  # broadcast / multicast
            res[ip] = mac
    return res


def rdns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


PRIVATE_MAC_VENDOR = "Private address (phone/laptop)"  # the "maker" shown for a randomised MAC


def is_private_mac(mac):
    """Locally administered (randomised) MACs - phones/laptops using 'private address'. A
    malformed MAC (it comes from routers and mesh systems) is simply not private."""
    try:
        return bool(mac) and int(mac.replace("-", ":").split(":")[0], 16) & 0x02 != 0
    except (ValueError, TypeError, AttributeError):  # not a MAC, or not even text
        return False


# --------------------------------------------------------------------------- vendor lookup
_OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
_oui, _oui_lock = None, threading.Lock()


def _load_oui():
    table = {}
    with open(OUI_PATH, encoding="utf-8", errors="replace", newline="") as f:
        for row in csv.reader(f):
            if len(row) >= 3 and len(row[1]) == 6:
                table[row[1].upper()] = row[2].strip()
    return table


def fetch_oui():
    """Download the IEEE vendor list once (~3 MB); vendors simply stay blank if offline."""
    global _oui
    if not os.path.exists(OUI_PATH) or time.time() - os.path.getmtime(OUI_PATH) > 180 * 86400:
        try:
            tmp = OUI_PATH + ".part"
            req = urllib.request.Request(_OUI_URL, headers={"User-Agent": "hearth"})
            with urllib.request.urlopen(req, timeout=60) as r, open(tmp, "wb") as f:
                f.write(r.read())
            os.replace(tmp, OUI_PATH)
        except Exception as e:
            log(f"vendor list download failed ({e}); vendors will be blank")
            return
    with _oui_lock:
        _oui = _load_oui()


def vendor(mac):
    if not mac:
        return None
    if is_private_mac(mac):
        return PRIVATE_MAC_VENDOR
    with _oui_lock:
        table = _oui
    return table.get(mac.replace(":", "").replace("-", "")[:6].upper()) if table else None


def radio_owner(bssid, macs):
    """Map a WiFi radio's BSSID to the LAN device that broadcasts it. Access points derive
    BSSIDs from their base MAC: same middle bytes, last byte nearby, first byte often
    with the locally-administered bit set. Returns the matching MAC or None."""
    try:
        b = [int(x, 16) for x in bssid.split(":")]
    except ValueError:
        return None
    best = None
    for mac in macs:
        try:
            m = [int(x, 16) for x in mac.split(":")]
        except ValueError:
            continue
        if b[1:5] == m[1:5] and abs(b[5] - m[5]) <= 8:
            d = abs(b[5] - m[5]) + (0 if b[0] == m[0] else 1)
            if best is None or d < best[0]:
                best = (d, mac)
    return best[1] if best else None
