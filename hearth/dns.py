"""Step 4, part 3a (#88): is DNS answering? Once a minute Hearth asks each resolver for the
address of one well-known name over plain UDP, and times the answer.

Only the reply's 12-byte header is used: its ID must match the question's, it must be a
response, and its RCODE says whether the resolver could answer. Nothing else in a reply is read,
so a malformed or spoofed packet can only count as "no answer".

Resolvers are limited to the router, an address on Hearth's own LAN (a Pi-hole), and six
well-known public resolvers - nothing else is ever sent a packet (design, section 4.5)."""
import ipaddress
import os
import re
import socket
import struct
import time

PUBLIC_RESOLVERS = ("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112")
GATEWAY = "gateway"            # in dns_resolvers: whatever the router's address is
TIMEOUT_S = 2.0
PORT = 53
MAX_RESOLVERS = 3
_LABEL = re.compile(r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
RCODE_WORDS = {0: "answered", 1: "format error", 2: "server failure", 3: "no such name", 4: "not implemented",
               5: "refused"}


def valid_name(name):
    """A hostname: at most 253 characters of dot-separated labels, each 1-63 letters, digits or
    hyphens, not starting or ending with a hyphen."""
    if not isinstance(name, str) or not 0 < len(name) <= 253:
        return False
    return all(_LABEL.fullmatch(label) for label in name.rstrip(".").split("."))


def build_query(name, qid):
    """A standard query (recursion desired) for the A record of `name`. ValueError for a name
    valid_name refuses."""
    if not valid_name(name) or not 0 <= qid <= 0xFFFF:
        raise ValueError(f"not a name Hearth will ask for: {name!r}")
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.rstrip(".").split(".")) + b"\x00"
    return header + qname + struct.pack(">HH", 1, 1)


def parse_reply(data, qid):
    """The RCODE of a reply to question `qid`, or None when it isn't one: too short for a header,
    another ID, or not a response."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 12:
        return None
    rid, flags = struct.unpack(">HH", data[:4])
    if rid != qid or not flags & 0x8000:
        return None
    return flags & 0x000F


def probe(resolver, name, timeout=TIMEOUT_S):
    """Ask `resolver` for `name` once: (milliseconds, rcode), or (None, None) when no matching
    reply came within `timeout`. Replies that don't match are ignored, not trusted."""
    qid = int.from_bytes(os.urandom(2), "big")
    packet = build_query(name, qid)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        start = time.perf_counter()
        s.sendto(packet, (resolver, PORT))
        deadline = start + timeout
        while True:
            left = deadline - time.perf_counter()
            if left <= 0:
                return None, None
            s.settimeout(left)
            try:
                data, addr = s.recvfrom(512)
            except (socket.timeout, ConnectionResetError):   # Windows: ICMP unreachable shows as a reset
                return None, None
            rcode = parse_reply(data, qid) if addr[0] == resolver else None
            if rcode is not None:
                return round((time.perf_counter() - start) * 1000, 1), rcode


def allowed(ip, gateway, lan):
    """Whether Hearth may send `ip` a DNS question: the router, an address on its own LAN, or one
    of PUBLIC_RESOLVERS."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError, TypeError):
        return False
    if str(addr) in PUBLIC_RESOLVERS or (gateway and str(addr) == gateway):
        return True
    return bool(lan) and addr in lan and addr not in (lan.network_address, lan.broadcast_address)


def resolvers(configured, gateway, lan):
    """The resolvers to ask, in order: `configured` (dns_resolvers) with "gateway" replaced by
    the router's address, each kept only if allowed(), no repeats, at most MAX_RESOLVERS.
    Returns (resolvers, refused) - the refused ones are reported, never asked."""
    out, refused = [], []
    for item in configured if isinstance(configured, list) else []:
        ip = gateway if item == GATEWAY else item
        if ip and allowed(ip, gateway, lan):
            if ip not in out and len(out) < MAX_RESOLVERS:
                out.append(ip)
        elif item != GATEWAY:
            refused.append(str(item)[:64])
    return out, refused
