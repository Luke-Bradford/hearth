"""The Security panel (#131): what can reach this home from the internet, and whether the
router and mesh firmware are known - from the router's own settings (read-only, hourly) and
the mesh's node list. Each way in is a plain sentence with a level; what's closed is one line."""
import time

from . import analysis, levels as lv, mesh, naming, router, store

PROTO_WORDS = {"tcp": "TCP", "udp": "UDP", "tcp udp": "TCP and UDP"}
# what each setting means when it's on: (level, sentence); off ones are listed together as closed
ON = {
    "dmz": (lv.BAD, "The DMZ is on: every connection from the internet that no forward takes goes to one device."),
    "admin_https": (lv.BAD, "The router's admin page can be reached from the internet."),
    "admin_ssh": (lv.BAD, "The router's SSH login can be reached from the internet."),
    "cloud_ssh": (lv.WARN, "GL.iNet's cloud can open an SSH session on the router."),
    "cloud_web": (lv.WARN, "GL.iNet's cloud can open the router's admin page remotely."),
    "cloud": (lv.WARN, "The router is linked to GL.iNet's cloud (GoodCloud), which can manage it remotely."),
    "upnp": (lv.WARN, "UPnP is on: devices at home can open ports to the internet themselves (games consoles, some "
                      "cameras). Turn it off if nothing needs it."),
    "tailscale": (lv.UNKNOWN, "Tailscale is on: devices signed in to your Tailscale account can reach the home network."),
    "zerotier": (lv.UNKNOWN, "ZeroTier is on: devices in your ZeroTier network can reach the home network."),
    "wireguard": (lv.UNKNOWN, "The router's WireGuard VPN server is running: devices with its key can join the home network."),
    "openvpn": (lv.UNKNOWN, "The router's OpenVPN server is running: devices with its profile can join the home network."),
    "ddns": (lv.UNKNOWN, "Dynamic DNS is on: a name on the internet follows your home's address."),
    "ping": (lv.UNKNOWN, "The router answers ping from the internet."),
}
CLOSED_WORDS = {"dmz": "DMZ", "admin_https": "admin page", "admin_ssh": "SSH", "upnp": "UPnP", "cloud": "GL.iNet cloud",
                "tailscale": "Tailscale", "zerotier": "ZeroTier", "wireguard": "WireGuard", "openvpn": "OpenVPN",
                "ddns": "dynamic DNS"}
# unknown, these keep the panel from saying all is well: the ways in that matter most
CRITICAL = {"port forwards", "DMZ", "admin page", "SSH"}


def _item(key, level, text):
    return {"key": key, "level": level, "text": text}


def _names_by_ip(conn, now):
    """{ip: (name, on the network now)}: Hearth's devices (the online row wins where an address
    was reused), then the router's fresh client list (its name for a device, and it sees every
    device - Hearth's own computer included, which Hearth doesn't list), then this computer."""
    out = {}
    for r in sorted(naming.device_rows(conn), key=lambda r: (r[5] or 0, r[7] or 0)):
        out[r[1]] = (r[8], bool(r[5]))
    for ip, name, online in conn.execute("SELECT ip, name, online FROM router_clients WHERE last_seen >= ? AND ip IS NOT NULL",
                                         (now - naming.ROUTER_FRESH_S,)):
        if online:
            out[ip] = (name or out.get(ip, (ip, False))[0], True)
    me = analysis._my_ip()
    if me:
        out[me] = (f"{out.get(me, ('this computer', True))[0]} (the computer running Hearth)", True)
    return out


def view(conn, now=None):
    """/api/security: {"available", "level", "items": [{key, level, text}], "firmware": [{what,
    version, date}], "read": when}. Not available until the router has been read."""
    now = now if now is not None else time.time()
    sec = router.security_now(conn, now)
    firmware = []
    snap = store.get_state(conn, mesh.MESH_STATE_KEY) or {}
    for n in snap.get("nodes", []) if isinstance(snap, dict) else []:
        if isinstance(n, dict) and n.get("firmware"):
            firmware.append({"what": f"{n.get('name') or 'Mesh unit'} (mesh)", "version": n["firmware"], "date": None})
    if not sec:
        return {"available": False, "level": lv.UNKNOWN, "items": [], "firmware": firmware, "read": None}
    fw = sec.get("firmware") or {}
    if fw.get("version"):
        firmware.insert(0, {"what": f"Router ({fw.get('model') or 'GL.iNet'})", "version": fw["version"], "date": fw.get("date")})
    items, closed, unread = [], [], []
    names = _names_by_ip(conn, now)
    if sec.get("forwards") is None:
        unread.append("port forwards")
    for f in sec.get("forwards") or []:
        if not f.get("enabled"):
            continue
        if f.get("unreadable"):
            items.append(_item("forward", lv.WARN, f"A port forward{' (' + f['name'] + ')' if f.get('name') else ''} "
                                                   "that Hearth can't read - see the router's Port Forwarding page."))
            continue
        port = f["port"] if f["port"] == f["to_port"] else f"{f['port']} (to port {f['to_port']})"
        who, online = names.get(f["to_ip"], (None, False))
        where = f"{who} · {f['to_ip']}" if who and f["to_ip"] not in who else (who or f["to_ip"])
        what = f"{f['name']}: p" if f.get("name") else "P"
        if online:
            items.append(_item("forward", lv.UNKNOWN, f"{what}ort {port} ({PROTO_WORDS.get(f['proto'], f['proto'])}) is "
                                                      f"open to {where}."))
        elif who:
            # a device Hearth knows that's just off (a console, a sleeping laptop): noted, not a
            # warning - it would raise an alert every time it's switched off (#132 review)
            items.append(_item("forward", lv.UNKNOWN, f"{what}ort {port} ({PROTO_WORDS.get(f['proto'], f['proto'])}) is "
                                                      f"open to {where}, which is off right now."))
        else:
            items.append(_item("forward", lv.WARN, f"{what}ort {port} is forwarded to {where}, which isn't on the "
                                                   "network now - an old rule? Remove it in the router if nothing uses it."))
    for key, (level, text) in ON.items():
        if sec.get(key) is True:
            items.append(_item(key, level, text))
        elif sec.get(key) is False and key in CLOSED_WORDS:
            closed.append(CLOSED_WORDS[key])
        elif sec.get(key) is None and key in CLOSED_WORDS:
            unread.append(CLOSED_WORDS[key])   # not known: never counted as closed (security review)
    items.sort(key=lambda i: -lv.rank(i["level"]))
    if closed:
        items.append(_item("closed", lv.OK, "Closed: " + ", ".join(closed) + "."))
    if unread:
        items.append(_item("unread", lv.UNKNOWN, "Couldn't read from the router: " + ", ".join(unread) + "."))
    if any(i["level"] in (lv.WARN, lv.BAD) for i in items):
        worst = lv.worst([i["level"] for i in items if i["level"] in (lv.WARN, lv.BAD)])
    elif set(unread) & CRITICAL:
        worst = lv.UNKNOWN   # the biggest ways in aren't known: not "all fine"
    else:
        worst = lv.OK
    return {"available": True, "level": worst, "items": items, "firmware": firmware, "read": sec.get("ts")}


def security_view(conn, _minutes):   # the cached(fn, conn, minutes) shape: the cache keys on the name
    return view(conn)


def attention(conn, now):
    """The Security panel's warnings and problems, for "Needs attention" - from the same cached
    view /api/security serves (it changes hourly), not worked out again each time (#133)."""
    v = analysis.cached(security_view, conn, 60, ttl=60)
    return [i for i in v["items"] if i["level"] in (lv.WARN, lv.BAD)] if v["available"] else []
