"""Device identity and human-readable names. User labels (set from the dashboard) win;
otherwise names come from what devices announce (mDNS / UPnP), hostnames, MAC vendors and
IPs - nothing is configured by hand."""
import re
import time

from .config import (GROUP_PREFIX, KEEP_SWEEPS, MESH_STATE_KEY, STATE_ASLEEP, STATE_OFFLINE, STATE_ONLINE,
                     device_target)
from .ids import looks_like_id
from .net import PRIVATE_MAC_VENDOR
from . import store


def shared_ips(conn):
    """IPs whose MAC is shared with other IPs (a repeater answering for devices behind it)."""
    return set(store.get_state(conn, "shared_mac_ips", []))


def normalise_mac(mac):
    """aa:bb:cc:dd:ee:ff whatever the source wrote (upper case, dashes)."""
    return mac.replace("-", ":").lower() if mac else mac


def device_id(mac, ip, shared):
    """The single rule for a device's id: its MAC, unless that MAC is shared - then its IP."""
    return device_target(None if ip in shared else normalise_mac(mac), ip)


def _useful_hostname(name):
    """Reverse-DNS names like 'ecb5fa1a2b3c.lan' (a MAC) or a UUID say nothing to a person."""
    if not name:
        return None
    return None if looks_like_id(name.split(".")[0]) else name


def fallback_name(vendor, where):
    """For a device nothing names: "maker · IP" (or "· MAC" when it has no IP); a randomised
    MAC's maker reads "Private address (...)". Just the IP / MAC when the maker is unknown.
    Registry maker names are cut to their first part and 28 characters; our own label is not."""
    if not vendor:
        return where
    maker = vendor if vendor == PRIVATE_MAC_VENDOR else vendor.split(",")[0][:28]
    return f"{maker} · {where}"


def router_names(conn):
    """{mac: name} from the router's client list (DHCP hostnames and names set in its UI)."""
    return {normalise_mac(m): n for m, n in conn.execute("SELECT mac, name FROM router_clients")
            if n and not looks_like_id(n)}


PLACEHOLDER_NAME = re.compile(r"^(Device|Client)_[0-9A-Fa-f]{4}$")  # the mesh's name for unnamed devices


def mesh_names(conn):
    """Names from the mesh system's last reading: (mesh nodes by MAC and by IP, as named in
    its app; its clients by MAC, skipping placeholders like "Device_5C6C")."""
    snap = store.get_state(conn, MESH_STATE_KEY) or {}
    nodes, node_ips, clients = {}, {}, {}
    for n in snap.get("nodes", []):
        if n.get("name"):
            label = f"{n['name']} ({n['model']})" if n.get("model") else n["name"]
            nodes[n["mac"]] = label
            if n.get("ip"):
                node_ips[n["ip"]] = label
    for c in snap.get("clients", []):
        name = c.get("name")
        if name and not PLACEHOLDER_NAME.match(name) and not looks_like_id(name):
            clients[c["mac"]] = name
    return nodes, node_ips, clients


def device_rows(conn):
    """[(id, ip, mac, hostname, vendor, online, first_seen, last_seen, display, friendly, model, state)]
    for every known device. Display name: your label > the mesh app's name for a mesh node >
    its mDNS name > the router's name for it > the mesh's name for it > hostname > its UPnP
    name > maker. friendly is the announced name (mDNS, else UPnP)."""
    labels, shared = store.labels(conn), shared_ips(conn)
    routed = router_names(conn)
    mesh_nodes, mesh_node_ips, mesh_clients = mesh_names(conn)
    raw = []  # (row, named by the user?)
    cutoff, idle = asleep_cutoff(conn), router_offline(conn)
    for ip, mac, name, vendor, online, first, last, friendly, app_name, model, answered in conn.execute(
            "SELECT ip, mac, name, vendor, online, first_seen, last_seen, friendly, app_name, model, last_answered "
            "FROM devices"):
        mac = normalise_mac(mac)
        state = device_state(online, answered, cutoff, mac in idle)
        tid = device_id(mac, ip, shared)
        if tid in labels:
            display, user = labels[tid], True
        else:
            # the machine's own names first; a UPnP name may be an app's (an antivirus agent on
            # a PC), so it only names devices that have nothing better, e.g. a TV
            display = (mesh_nodes.get(mac) or mesh_node_ips.get(ip) or friendly or routed.get(mac)
                       or mesh_clients.get(mac) or _useful_hostname(name) or app_name
                       or fallback_name(vendor, ip))
            user = False
        raw.append(([tid, ip, mac, name, vendor, online, first, last, display, friendly or app_name, model, state],
                    user))
    # two interfaces of one machine (e.g. a Mac's wired and WiFi) announce the same name. Counted
    # by device, not row: a device's own older addresses (the same id) aren't a clash (#122)
    ids_by_name = {}
    for r, _ in raw:
        ids_by_name.setdefault(r[8], set()).add(r[0])
    out = []
    for r, user in raw:
        if len(ids_by_name[r[8]]) > 1 and not user and "·" not in r[8]:
            r[8] = f"{r[8]} · {r[1]}"
        out.append(tuple(r))
    return out


def asleep_cutoff(conn):
    """A device whose last ping answer is older than this went unanswered in each of the last
    KEEP_SWEEPS sweeps (the start of the oldest of them); None until that many have run.
    Counted in sweeps, not clock time, so a stalled sweep or a suspended host doesn't turn
    every device asleep."""
    starts = [s for (s,) in conn.execute("SELECT start FROM sweeps ORDER BY start DESC LIMIT ?", (KEEP_SWEEPS,))]
    return starts[-1] if len(starts) == KEEP_SWEEPS else None


ROUTER_FRESH_S = 600   # the router's client list is rewritten each poll: older rows aren't evidence


def router_offline(conn, now=None):
    """MACs the router's latest client list (read in the last ROUTER_FRESH_S) calls offline."""
    now = now if now is not None else time.time()
    return {normalise_mac(m) for (m,) in conn.execute(
        "SELECT mac FROM router_clients WHERE online = 0 AND last_seen >= ?", (now - ROUTER_FRESH_S,))}


def device_state(online, last_answered, cutoff, router_says_offline=False):
    """online / asleep / offline. Asleep: still on the network (seen in the ARP table) but it
    answered no ping in the last KEEP_SWEEPS sweeps after answering before - a sleeping PC's
    network card often keeps answering ARP. A device that never answers ping (a firewalled or
    managed laptop) is online unless the router says otherwise: then it's the same sleeping card
    answering ARP for a machine that isn't using the network (#122)."""
    if not online:
        return STATE_OFFLINE
    if last_answered is not None and cutoff is not None and last_answered < cutoff:
        return STATE_ASLEEP
    if last_answered is None and router_says_offline:
        return STATE_ASLEEP
    return STATE_ONLINE


def device_names(conn):
    """{device id: display name}. When old rows share an id, the online/most recent one wins.
    Ids recorded under an older rule (MAC-keyed, before a MAC was found to be shared) still
    resolve, so history from before the change keeps its names."""
    rows = sorted(device_rows(conn), key=lambda r: (r[5] or 0, r[7] or 0))  # oldest/offline first
    mac_rows = {}
    for r in rows:
        if r[2]:
            mac_rows[r[2]] = mac_rows.get(r[2], 0) + 1
    names = {}
    for r in rows:
        # legacy MAC-keyed id: only when the MAC belongs to a single device (a shared MAC would
        # give old history an unrelated device's name); later rows overwrite, so the
        # online/most recent one wins
        if r[2] and mac_rows[r[2]] == 1:
            names[device_target(r[2], r[1])] = r[8]
    for r in rows:
        names[r[0]] = r[8]
    return names


_ROLE_DEFAULT = {"local": "This computer's segment", "relay": "Relay via", "branch": "Branch via"}


def _lead(devnames, members, floors=None):
    """The member a group is named after: the lowest-latency one (usually the extender or mesh
    node the others hang off)."""
    floors = floors or {}
    return min(members, key=lambda m: (floors.get(m) is None, floors.get(m) or 0, devnames.get(m, m)))


def group_label(labels, devnames, gid, members, role, floors=None):
    """The group's own name, for use inside a sentence ("goes via X", "link to X"): the user's
    name for it, or its closest member - the lowest-latency one, usually the extender or mesh
    node the others hang off."""
    if GROUP_PREFIX + str(gid) in labels:
        return labels[GROUP_PREFIX + str(gid)]
    if role == "local":
        return _ROLE_DEFAULT["local"]
    lead = _lead(devnames, members, floors)
    others = len(members) - 1
    return devnames.get(lead, lead) + (f" (+{others})" if others else "")


def group_short(labels, devnames, gid, members, role, floors=None):
    """The shortest fitting name, for a map where the members are drawn anyway: your name for
    the group, or its closest member alone (no "(+2)", no "Branch via")."""
    if GROUP_PREFIX + str(gid) in labels or role == "local":
        return group_label(labels, devnames, gid, members, role, floors)
    lead = _lead(devnames, members, floors)
    return devnames.get(lead, lead)


def group_name(labels, devnames, gid, members, role, floors=None):
    """The group's title on its own (a card heading): its label with the role in front,
    e.g. "Branch via Extender 1 (+2)", unless the user named it."""
    label = group_label(labels, devnames, gid, members, role, floors)
    if GROUP_PREFIX + str(gid) in labels or role == "local":
        return label
    return f"{_ROLE_DEFAULT[role]} {label}"
