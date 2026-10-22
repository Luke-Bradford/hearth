"""Background threads that gather data. Each owns its own SQLite connection and never dies
on a database error (it rolls back and retries on the next cycle)."""
import ctypes
import ipaddress
import json
import math
import os
import queue
import re
import sqlite3
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import (alerts, analysis, backup, digest, dns, dns_health, host, identify, live, mesh, net, notify, router, settings, sources,
               speedtest, store, topology, upnp)
from .config import (CFG, EV_ISP_PATH, EV_MESH, EV_PATH, EV_ROUTER, EV_WIFI_BACK, EV_WIFI_CHANNEL, EV_WIFI_LOST,
                     GATEWAY_STATE_KEY, KEEP_SWEEPS, OFFLINE_AFTER_MISSES, TARGET_GATEWAY, TARGET_ISP,
                     inet_target, log)
from .naming import device_id, device_names, device_rows, group_label, normalise_mac

samples_q = queue.Queue()


class Targets:
    """What is being pinged right now. Core targets (router, ISP edge, internet) are pinged
    every second each; LAN devices are pinged together on one tick every few seconds so their
    samples share timestamps (the topology inference compares them moment by moment)."""

    def __init__(self):
        self._lock = threading.Lock()
        self.core = {}      # id -> ip
        self.devices = {}   # id -> ip

    def set_core(self, tid, ip):
        with self._lock:
            if ip:
                self.core[tid] = ip
            else:
                self.core.pop(tid, None)

    def set_devices(self, mapping):
        with self._lock:
            self.devices = dict(mapping)

    def snapshot(self):
        with self._lock:
            return dict(self.core), dict(self.devices)


TARGETS = Targets()


def _fail_safe(name, conn, fn):
    """Run fn and commit; on a database error log, roll back and return False."""
    try:
        fn()
        conn.commit()
        return True
    except sqlite3.Error as e:
        log(f"{name}: {e} - will retry")
        conn.rollback()
        return False


# --------------------------------------------------------------------------- pinging
def core_ping_loop(tid, stop):
    p = net.Pinger()
    interval, timeout = float(CFG["core_interval_s"]), int(CFG["ping_timeout_ms"])
    nxt = time.time()
    try:
        while not stop.is_set():
            ip = TARGETS.snapshot()[0].get(tid)
            if ip is None:
                return  # target retired (e.g. ISP edge stopped answering)
            ts = time.time()
            try:
                rtt = p.ping(ip, timeout)
            except Exception as e:  # a probe failure must not end this target's monitoring
                log(f"ping {tid}: {e}")
                rtt = None
            samples_q.put((ts, tid, rtt))
            live.record_ping(tid, ts, rtt)
            nxt += interval
            delay = nxt - time.time()
            if delay < 0:
                nxt = time.time()
            else:
                stop.wait(delay)
    finally:
        p.close()


class CorePingers:
    """Starts a pinger thread per core target and replaces it when the target set changes."""

    def __init__(self, stop):
        self.stop, self.threads, self._lock = stop, {}, threading.Lock()

    def sync(self):
        # called from the discovery and path threads: the lock stops both starting a pinger
        # for the same target (which would double its sample rate)
        with self._lock:
            core, _ = TARGETS.snapshot()
            for tid in [t for t, th in self.threads.items() if not th.is_alive() and t not in core]:
                del self.threads[tid]  # retired targets whose pinger has exited
            for tid in core:
                t = self.threads.get(tid)
                if t is None or not t.is_alive():
                    t = threading.Thread(target=core_ping_loop, args=(tid, self.stop), daemon=True,
                                         name=f"ping-{tid}")
                    self.threads[tid] = t
                    t.start()


class PollPacer:
    """Decides which devices to ping on each tick. Devices that keep missing replies on their
    own (phones asleep, laptops in power save, or a device on a genuinely lossy link) are
    checked once a minute instead of every few seconds: frequent pings would only wake their
    radios and cost battery, and their replies are too erratic to help work out the layout.
    Trade-off: such a device's own loss is then sampled once a minute. Misses that happen to
    most devices at once (an outage) never count, so outages stay fully sampled."""

    WINDOW = 12            # recent results remembered per device
    SLEEPY_LOSS = 0.2      # miss more than this share of them -> slow down
    WAKE_STREAK = 3        # this many replies in a row -> back to normal straight away

    def __init__(self, normal_s, sleepy_s):
        self.normal_s, self.sleepy_s = normal_s, sleepy_s
        self.recent, self.next_due = {}, {}

    def sleepy(self, tid):
        r = self.recent.get(tid)
        return bool(r) and len(r) >= 4 and r.count(False) / len(r) > self.SLEEPY_LOSS

    def due(self, devices, now):
        for tid in set(self.recent) | set(self.next_due):
            if tid not in devices:  # forgotten devices don't keep state forever
                self.recent.pop(tid, None)
                self.next_due.pop(tid, None)
        return [t for t in devices if now >= self.next_due.get(t, 0)]

    def record_tick(self, results, now):
        """results: [(device id, answered)] for one tick. If most devices missed at once, that's
        an outage or this computer stalling, not the devices sleeping: misses from such a tick
        don't count towards "sleepy", so devices stay sampled every few seconds exactly when
        the analysis needs it most."""
        # judged on the devices that normally answer: sleepy ones (due once a minute) missing
        # together with a few others mustn't make a small tick look like an outage
        awake = [ok for tid, ok in results if not self.sleepy(tid)]
        outage = len(awake) >= 4 and awake.count(False) / len(awake) > 0.5
        for tid, ok in results:
            if outage and not ok:
                # still due again at the normal (or current) rate, but don't mark it sleepy
                self.next_due[tid] = now + (self.sleepy_s if self.sleepy(tid) else self.normal_s) - 0.5
                continue
            self.record(tid, ok, now)

    def record(self, tid, answered, now):
        r = self.recent.setdefault(tid, [])
        r.append(answered)
        del r[:-self.WINDOW]
        # at one ping a minute, old misses would take ~10 min to age out; a short run of
        # replies is enough evidence the device is awake again
        if self.sleepy(tid) and len(r) >= self.WAKE_STREAK and all(r[-self.WAKE_STREAK:]):
            del r[:-self.WAKE_STREAK]
        # half a second of slack keeps a device on the same tick grid as the others
        self.next_due[tid] = now + (self.sleepy_s if self.sleepy(tid) else self.normal_s) - 0.5


def device_poll_loop(stop):
    interval, timeout = float(CFG["device_interval_s"]), min(int(CFG["ping_timeout_ms"]), 1500)
    tls, pingers, plock = threading.local(), [], threading.Lock()

    def ping(ip):
        p = getattr(tls, "pinger", None)
        if p is None:
            p = tls.pinger = net.Pinger()
            with plock:
                pingers.append(p)  # remembered so the handles are closed when this loop ends
        try:
            return p.ping(ip, timeout)
        except Exception:
            return None

    pacer = PollPacer(interval, float(CFG["sleepy_interval_s"]))
    try:
        with ThreadPoolExecutor(max_workers=16, thread_name_prefix="devping") as ex:
            nxt = time.time()
            while not stop.is_set():
                _, devices = TARGETS.snapshot()
                ts = time.time()  # one timestamp for the whole tick
                ids = pacer.due(devices, ts)
                results = list(zip(ids, ex.map(lambda t: ping(devices[t]), ids)))
                pacer.record_tick([(tid, rtt is not None) for tid, rtt in results], ts)
                for tid, rtt in results:
                    samples_q.put((ts, tid, rtt))
                    live.record_ping(tid, ts, rtt)
                nxt += interval
                delay = nxt - time.time()
                if delay < 0:
                    nxt = time.time()
                else:
                    stop.wait(delay)
    finally:
        for p in pingers:
            p.close()


def writer_loop(stop):
    conn = store.db()
    last_prune = last_roll = 0
    while not stop.is_set():
        stop.wait(2)
        rows = []
        while True:
            try:
                rows.append(samples_q.get_nowait())
            except queue.Empty:
                break
        try:
            if rows:
                conn.executemany("INSERT INTO pings VALUES (?,?,?)", rows)
                conn.commit()
                rows = []
            now = time.time()
            if now - last_roll > 60:
                # a minute is rolled up once, so wait well past its end for slow samples
                # (a 5 s device tick plus the 2 s write batch) before closing it
                store.rollup(conn, now - 30)
                store.rollup_hourly(conn, now)   # cheap when no hour has closed: one MAX per table
                conn.commit()
                last_roll = now
            if now - last_prune > 3600:
                store.prune(conn, now)
                conn.commit()
                last_prune = now
        except sqlite3.Error as e:
            # never let the writer die: roll back, put samples back, retry next cycle
            log(f"writer: {e} - will retry")
            conn.rollback()
            for r in rows:
                samples_q.put(r)


# --------------------------------------------------------------------------- discovery
_oui_started = threading.Event()


ID_MOVES_KEY = "id_moves_pending"  # state row: id moves made last sweep, repeated once (late pings)
ID_OWNERS_KEY = "id_owners"         # state row: {device id: [ip, mac]} - whose rows a move left under it
# both are bounded: what goes into them is driven by MACs and IPs devices on the LAN announce,
# so a device faking many combinations must not be able to grow them without limit
ID_OWNERS_MAX = 256                 # ownership records kept (the most recent moves win)
ID_OWNER_GRACE_S = 3600             # a record outlives its rows this long (late rows arrive within a sweep)
_BLOCKED_LOG_MAX = 256              # blocked moves remembered as already logged
_blocked_moves_logged = set()       # (old id, new id) pairs already reported as blocked


def shared_mac_ips(seen, arp, still_present):
    """IPs whose MAC is also used by another present IP. Present: seen in this sweep (MAC from
    the ARP table), or not seen but still online - within the offline grace - with the MAC it
    was last seen with (still_present: {ip: mac})."""
    macs = {ip: normalise_mac(arp[ip]) for ip in seen if arp.get(ip)}
    for ip, mac in still_present.items():
        if ip not in macs and mac:
            macs[ip] = normalise_mac(mac)
    count = {}
    for mac in macs.values():
        count[mac] = count.get(mac, 0) + 1
    return {ip for ip, mac in macs.items() if count[mac] > 1}


def follow_id_changes(conn, known, old_shared, new_shared, arp, seen, now):
    """A device's id is its MAC, unless the MAC is shared by several IPs (a repeater answering
    for the devices behind it) - then its IP. When an IP moves between those cases, move its
    history and name to the new id (#3) - only when it's clear whose history it is, so one
    device's history never lands on another:
    - MAC became shared: the MAC-keyed history goes to the one IP that was online with that
      MAC before this sweep, if that IP's own id is free; if several were, it's ambiguous and
      nothing moves.
    - MAC stopped being shared: only for an IP seen in this sweep that is now the *only* IP
      with that MAC, and only if the MAC id is free (nothing of an earlier owner's under it) -
      its IP-keyed history goes to the MAC id. An IP that merely went offline
      also leaves the shared set (sharing is judged on what each sweep sees); it keeps its
      history, and keeps its id when it comes back.
    "Free" means nothing is stored under the id, or only this device's own leftovers from an
    earlier move (moves never delete, so a flapping device leaves some). A blocked move is
    logged once: the device's id still changes, so its history and name stay under the old id.
    Pings already queued under the old id can be written just after a move, so each move is
    repeated once on the next sweep to carry those over too."""
    for move in store.get_state(conn, ID_MOVES_KEY, []):
        # repeat last sweep's move only while that IP still maps to the same new id
        if isinstance(move, list) and len(move) == 4:
            old_id, new_id, ip, mac = move
            if device_id(mac, ip, new_shared) == new_id:
                store.move_device_history(conn, old_id, new_id)
    moves = []
    mac_of = lambda ip: normalise_mac(arp.get(ip) or (known.get(ip) or (None, None))[1])
    # id -> [ip, mac, when] for the device a move gave it to: it says whose leftovers the rows
    # under that id are. Records are dropped once the id holds nothing and the move is more
    # than ID_OWNER_GRACE_S old (by the sweep's clock), so an old record can't approve a merge
    # after the rows it described are gone
    id_owner = store.get_state(conn, ID_OWNERS_KEY, {})

    def free_for(tid, ip, mac):
        """Nothing under tid, or only this device's own leftovers from an earlier move."""
        if not store.id_in_use(conn, tid):
            return True
        rec = id_owner.get(tid)
        return isinstance(rec, list) and rec[:2] == [ip, mac]

    def consider(old_id, new_id, ip, mac):
        if free_for(new_id, ip, mac):
            moves.append((old_id, new_id, ip, mac))
        elif (old_id, new_id) not in _blocked_moves_logged:
            if len(_blocked_moves_logged) >= _BLOCKED_LOG_MAX:
                _blocked_moves_logged.clear()  # forget old ones: at worst a repeat log line
            _blocked_moves_logged.add((old_id, new_id))
            log(f"discovery: {ip}'s id changed from {old_id} to {new_id}, but {new_id} already holds another "
                f"device's history - its history and name stay under {old_id} (rename it on the dashboard)")

    owners = {}  # mac -> IPs that were online with it before this sweep
    for ip, row in known.items():
        if row[1] and row[3]:
            owners.setdefault(normalise_mac(row[1]), []).append(ip)
    for ip in new_shared - old_shared:
        mac = mac_of(ip)
        # the IP id must be free too (it may hold an earlier device's history from when that
        # address belonged to someone else): the same rule as the other direction
        if mac and owners.get(mac) == [ip]:
            consider(device_id(mac, ip, set()), device_id(mac, ip, {ip}), ip, mac)
    holders = {}  # mac -> IPs seen with it in this sweep
    for ip, mac in arp.items():
        if ip in seen:
            holders.setdefault(normalise_mac(mac), []).append(ip)
    for ip in old_shared - new_shared:
        mac = mac_of(ip)
        # the MAC id must be free: if it still holds history (an earlier owner's, left there
        # because ownership was ambiguous), this device's history mustn't be merged into it
        if mac and holders.get(mac) == [ip]:
            consider(device_id(mac, ip, {ip}), device_id(mac, ip, set()), ip, mac)
    for old_id, new_id, ip, mac in moves:
        store.move_device_history(conn, old_id, new_id)
        id_owner.pop(old_id, None)  # re-added below, last = most recent
        id_owner.pop(new_id, None)
        id_owner[old_id] = id_owner[new_id] = [ip, mac, now]  # both ids now hold this device's rows
    if moves or id_owner:
        def recent(rec):
            when = rec[2] if isinstance(rec, list) and len(rec) == 3 else None
            # a future time (a clock step, an edited row) isn't recent either
            return (isinstance(when, (int, float)) and not isinstance(when, bool)
                    and 0 <= now - when < ID_OWNER_GRACE_S)
        kept = {tid: o for tid, o in id_owner.items() if recent(o) or store.id_in_use(conn, tid)}
        kept = dict(list(kept.items())[-ID_OWNERS_MAX:])
        if kept != id_owner or moves:
            store.set_state(conn, ID_OWNERS_KEY, kept)
    store.set_state(conn, ID_MOVES_KEY, [list(m) for m in moves])


def record_sweep(conn, seen, answered, arp, names, shared, missed, now):
    """Write one discovery sweep to the devices table. seen: IPs that answered ping or are in
    the ARP table; answered: those that answered ping (their last_answered moves on, which is
    what "asleep" is judged by). missed counts, per IP, the sweeps in a row an online device
    wasn't seen; it goes offline at OFFLINE_AFTER_MISSES, and the event says when it was last
    seen (it left somewhere between that sweep and the next). Returns the new counts and
    leaves `missed` alone, so the caller keeps them only if these writes commit."""
    missed = dict(missed)
    known = {r[0]: r for r in conn.execute("SELECT ip, mac, name, online, last_seen FROM devices")}
    follow_id_changes(conn, known, set(store.get_state(conn, "shared_mac_ips", [])), shared, arp, seen, now)
    labels = store.labels(conn)
    store.set_state(conn, "shared_mac_ips", sorted(shared))
    label = lambda mac, ip, name: labels.get(device_id(mac, ip, shared)) or name or ip
    for ip in sorted(seen, key=lambda a: tuple(int(x) for x in a.split("."))):
        missed.pop(ip, None)
        mac, vendor = arp.get(ip), net.vendor(arp.get(ip))
        if ip in known:
            if not known[ip][3]:
                store.add_event(conn, "device_online", f"{label(mac, ip, names[ip])} came online")
            if mac and known[ip][1] and mac != known[ip][1]:
                # DHCP gave this IP to a different device: don't inherit the old one's name
                conn.execute("UPDATE devices SET last_seen=?, online=1, mac=?, name=?, vendor=?, friendly=NULL, "
                             "app_name=NULL, model=NULL, last_answered=NULL, first_seen=? WHERE ip=?",
                             (now, mac, names[ip], vendor, now, ip))
            else:
                conn.execute("""UPDATE devices SET last_seen=?, online=1, mac=COALESCE(?, mac),
                                name=COALESCE(?, name), vendor=COALESCE(?, vendor) WHERE ip=?""",
                             (now, mac, names[ip], vendor, ip))
        else:
            conn.execute("INSERT INTO devices (ip, mac, name, first_seen, last_seen, online, vendor) "
                         "VALUES (?,?,?,?,?,1,?)", (ip, mac, names[ip], now, now, vendor))
            store.add_event(conn, "device_new",
                            f"New device {names[ip] or vendor or ''} {ip} {mac or ''}".strip())
        if ip in answered:
            conn.execute("UPDATE devices SET last_answered=? WHERE ip=?", (now, ip))
    for ip, row in known.items():
        if row[3] and ip not in seen:
            missed[ip] = missed.get(ip, 0) + 1
            if missed[ip] >= OFFLINE_AFTER_MISSES:
                missed.pop(ip)
                conn.execute("UPDATE devices SET online=0 WHERE ip=?", (ip,))
                seen_at = f" (last seen {time.strftime('%H:%M', time.localtime(row[4]))})" if row[4] else ""
                store.add_event(conn, "device_offline", f"{label(row[1], ip, row[2])} went offline{seen_at}")
    for ip in [ip for ip in missed if ip not in known or not known[ip][3]]:
        missed.pop(ip)  # forgotten or already offline: nothing to count
    return missed


def network_settings():
    gw = CFG.get("gateway") or net.default_gateway()
    lan = ipaddress.ip_network(CFG["discovery_subnet"]) if CFG.get("discovery_subnet") else net.local_network()
    return gw, lan, net.local_ip()


def discovery_loop(stop, core_pingers):
    conn = store.db()
    workers = int(CFG["discovery_workers"])  # few workers = gentle sweep that doesn't fake incidents
    excluded = set(CFG.get("exclude_ips") or [])
    if not _oui_started.is_set():  # once per process, not on every supervised restart
        _oui_started.set()
        threading.Thread(target=net.fetch_oui, daemon=True, name="oui").start()
    recent = []  # responders of the last few sweeps
    missed = {}  # ip -> sweeps in a row an online device wasn't seen (see record_sweep)
    warned = False
    while not stop.is_set():
        try:
            gw, lan, me = network_settings()
        except ValueError as e:  # malformed discovery_subnet: say so once, keep the core targets going
            if not warned:
                log(f"discovery: bad discovery_subnet in config.json ({e}) - LAN discovery off")
                warned = True
            gw, lan, me = CFG.get("gateway") or net.default_gateway(), None, net.local_ip()
        if gw:
            TARGETS.set_core(TARGET_GATEWAY, gw)
        for ip in CFG["internet_targets"]:
            TARGETS.set_core(inet_target(ip), ip)
        core_pingers.sync()
        if not lan:
            if not warned:
                log("discovery: can't work out the local network - set discovery_subnet in config.json")
                warned = True
            stop.wait(60)
            continue

        def probe(ip):
            p = net.Pinger()
            try:
                return ip, p.ping(ip, 600)
            finally:
                p.close()

        sweep_start = time.time()
        with ThreadPoolExecutor(max_workers=workers) as ex:
            answered = {ip for ip, r in ex.map(probe, net.scan_hosts(lan)) if r is not None}
        sweep_end = time.time()
        arp = net.read_arp()
        seen = answered | {ip for ip in arp if ipaddress.ip_address(ip) in lan}
        seen.discard(me)
        # reverse DNS can take seconds per miss: resolve in parallel, outside any transaction
        with ThreadPoolExecutor(max_workers=16) as ex:
            names = dict(zip(seen, ex.map(net.rdns, seen)))
        try:  # devices' own announced names (mDNS / UPnP); best effort, a few seconds
            announced = identify.identify(me) if me else {}
        except OSError as e:
            log(f"identify: {e}")
            announced = {}
        # WiFi repeaters often answer for the devices behind them with their own MAC, so a MAC
        # seen on several IPs doesn't identify one device: key those by IP instead. Judged
        # over devices still present - seen now, or online and within the offline grace - so
        # one missed sweep doesn't flip ids (and move history) back and forth
        try:
            still = dict(conn.execute("SELECT ip, mac FROM devices WHERE online=1"))
        except sqlite3.Error:
            still = {}
        shared = shared_mac_ips(seen, arp, still)
        now = time.time()

        result = {}

        def write():
            result["missed"] = record_sweep(conn, seen, answered, arp, names, shared, missed, now)
            for ip, info in announced.items():
                if ip in seen:  # only devices on our LAN that this sweep saw
                    conn.execute("UPDATE devices SET friendly=COALESCE(?, friendly), app_name=COALESCE(?, app_name), "
                                 "model=COALESCE(?, model) WHERE ip=?",
                                 (info["friendly"], info["app_name"], info["model"], ip))
            conn.execute("INSERT INTO sweeps VALUES (?,?)", (sweep_start, sweep_end))
            if gw:  # where the router is, for readers that can't look it up cheaply (mesh_view)
                store.set_state(conn, GATEWAY_STATE_KEY, {"ip": gw, "ts": now})

        if _fail_safe("discovery", conn, write):
            missed = result["missed"]  # committed: adopt the new counts (on a rollback keep the old ones)
        # ping only devices that answer ping (ARP-only entries would just read as 100% loss).
        # A device stays polled while it answered any of the last KEEP_SWEEPS sweeps (~15 min),
        # so a quiet spell doesn't drop it from its group; after that it is "not placed" until
        # it answers again.
        recent = (recent + [answered])[-KEEP_SWEEPS:]
        keep = set().union(*recent)
        TARGETS.set_devices({device_id(arp.get(ip), ip, shared): ip for ip in keep
                             if ip != gw and ip != me and ip not in excluded})
        stop.wait(float(CFG["discovery_interval_s"]))


# --------------------------------------------------------------------------- path to the ISP
ISP_EDGE_MAX_MISSES = 3


def paths_differ(a, b):
    """True only if a hop that answered both times changed, or the path got longer/shorter.
    Hops that didn't answer ('*', None) are unknown, not different - routers often skip
    traceroute replies under load."""
    if len(a) != len(b):
        return True
    return any(x and y and x != y for x, y in zip(a, b))


def path_loop(stop, core_pingers):
    """Traceroute to the first internet target. The first public hop after the router is the
    ISP's edge: pinging it splits 'broadband line' from 'the wider internet'."""
    conn = store.db()
    if not CFG["internet_targets"]:
        log("path: internet_targets is empty - ISP edge detection off")
        stop.wait()  # idle rather than crash-loop under the supervisor
        return
    dest = CFG["internet_targets"][0]
    isp, misses = None, 0
    while not stop.is_set():
        gw = TARGETS.snapshot()[0].get(TARGET_GATEWAY)
        hops = net.traceroute(dest)
        path = [ip for _, ip, _ in hops]
        after_gw = path[path.index(gw) + 1:] if gw in path else path[1:]
        candidate = next((ip for ip in after_gw if ip and ip != dest), None)  # first hop past the router
        answered = False
        if candidate:
            p = net.Pinger()
            try:
                # ISP routers deprioritise ICMP: one reply in five proves it's there
                answered = any(p.ping(candidate, 1000) is not None for _ in range(5))
            finally:
                p.close()
        if answered:
            isp, misses = candidate, 0
        elif isp:
            misses += 1
            if misses >= ISP_EDGE_MAX_MISSES:  # ~30 min of failed checks before giving up on it
                isp, misses = None, 0

        def write():
            prev = store.get_state(conn, "isp_path")
            if prev is not None and paths_differ(prev, path):
                store.add_event(conn, EV_ISP_PATH, "Route to the internet changed: "
                                + " > ".join(h or "*" for h in path))
            store.set_state(conn, "isp_path", path)
            store.set_state(conn, "isp_edge", isp)

        _fail_safe("path", conn, write)
        TARGETS.set_core(TARGET_ISP, isp)
        core_pingers.sync()
        stop.wait(float(CFG["path_check_interval_s"]))


# --------------------------------------------------------------------------- topology
_bad_groups_logged = set()  # group ids already reported as unreadable (once per process)


def _json_or_none(text):
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return None


def _group_members(text):
    """A groups row's members as a set of device ids, or None if the row is damaged."""
    members = _json_or_none(text)
    if isinstance(members, list) and all(isinstance(x, str) for x in members):
        return set(members)
    return None


def topology_loop(stop):
    conn = store.db()
    window = float(CFG["topology_window_min"]) * 60
    bucket = 5
    stop.wait(60)
    while not stop.is_set():
        now = time.time()
        core, devices = TARGETS.snapshot()
        series = {}
        try:
            for tid, ts, rtt in conn.execute("SELECT target, ts, rtt FROM pings WHERE ts >= ?", (now - window,)):
                series.setdefault(tid, []).append((ts, rtt))
            sweeps = conn.execute("SELECT start, end FROM sweeps WHERE end >= ?", (now - window,)).fetchall()
            previous = store.get_state(conn, "roles", {})
        except sqlite3.Error as e:  # e.g. "database is locked": skip this run, try again next interval
            log(f"topology: {e} - will retry")
            stop.wait(float(CFG["topology_interval_s"]))
            continue
        excluded = frozenset(b for s, e in sweeps for b in range(int(s // bucket) - 1, int(e // bucket) + 2))
        try:
            res = topology.infer(series, list(devices), TARGET_GATEWAY, over_ms=25, bucket_s=bucket,
                                 excluded_buckets=excluded, previous=previous if isinstance(previous, dict) else {})
        except (ValueError, TypeError, KeyError) as e:  # bad saved state: skip this run, don't crash-loop
            log(f"topology: inference failed ({e!r}) - will retry")
            res = None
        if res:
            def write():
                # match against groups seen recently; ids keep counting from the highest ever
                # used, so a pruned group's user label can never land on a new group. A row
                # whose members don't parse is skipped (and so ages out) rather than stopping
                # every run
                old = {}
                for gid, m in conn.execute("SELECT id, members FROM groups WHERE updated >= ?", (now - 7 * 86400,)):
                    members = _group_members(m)
                    if members is not None:
                        old[gid] = members
                    elif gid not in _bad_groups_logged:
                        _bad_groups_logged.add(gid)
                        log(f"topology: group {gid} has unreadable members - ignored")
                next_id = (conn.execute("SELECT MAX(id) FROM groups").fetchone()[0] or 0) + 1
                next_id = max(next_id, store.get_state(conn, "next_group_id", 1))
                groups = ([res["local"]] if res["local"] else []) + res["relays"] + res["branches"]
                matched, next_id = topology.match_groups(groups, old, next_id)
                store.set_state(conn, "next_group_id", next_id)
                for gid, members in matched:
                    conn.execute("INSERT OR REPLACE INTO groups VALUES "
                                 "(?,?,COALESCE((SELECT created FROM groups WHERE id=?),?),?)",
                                 (gid, json.dumps(sorted(members)), gid, now, now))
                entries = [{"group": gid, "members": members} for gid, members in matched]
                n_local, n_relay = (1 if res["local"] else 0), len(res["relays"])
                snap = {
                    "local": entries[0] if n_local else None,
                    "relays": entries[n_local:n_local + n_relay],
                    "branches": entries[n_local + n_relay:],
                    "unstable": res["unstable"], "roles": res["roles"], "gateway_floor": res["gateway_floor"],
                }
                store.set_state(conn, "roles", res["roles"])

                # the path (which relay groups we go through) must hold for two runs before we
                # announce it. The pending change lives in the state table, inside this same
                # transaction, so a failed commit rolls it back together with everything else.
                sig = [r["group"] for r in snap["relays"]]
                current = store.get_state(conn, "path_sig")
                pending = store.get_state(conn, "path_pending", {"sig": None, "streak": 0})
                if current is None:
                    store.set_state(conn, "path_sig", sig)
                elif sig != current:
                    streak = pending["streak"] + 1 if sig == pending["sig"] else 1
                    if streak >= 2:
                        store.set_state(conn, "path_sig", sig)
                        streak = 0
                        labels, devnames = store.labels(conn), device_names(conn)
                        if sig:
                            floors = {d: r.get("floor") for d, r in res["roles"].items()}
                            via = ", ".join(group_label(labels, devnames, r["group"], r["members"], "relay", floors)
                                            for r in snap["relays"])
                            store.add_event(conn, EV_PATH, f"Path changed: now goes via {via}")
                        else:
                            store.add_event(conn, EV_PATH, "Path changed: now goes direct to the router")
                    store.set_state(conn, "path_pending", {"sig": sig if streak else None, "streak": streak})
                else:
                    store.set_state(conn, "path_pending", {"sig": None, "streak": 0})

                last = conn.execute("SELECT ts, data FROM topology ORDER BY ts DESC LIMIT 1").fetchone()
                shape = lambda s: json.dumps({k: s[k] for k in ("local", "relays", "branches")}, sort_keys=True)
                prior = _json_or_none(last[1]) if last else None
                if not isinstance(prior, dict) or not all(k in prior for k in ("local", "relays", "branches")) \
                        or shape(prior) != shape(snap) or now - last[0] > 1800:
                    conn.execute("INSERT INTO topology VALUES (?,?)", (now, json.dumps(snap)))

            _fail_safe("topology", conn, write)
        stop.wait(float(CFG["topology_interval_s"]))


SPIKE_HOURS_INTERVAL_S = 300  # the "usual" spike rate's hourly rows: a few hours every 5 minutes


def store_episodes_once(conn):
    """Store the final episodes (analysis.store_episodes) and record how it went, so a store
    that keeps failing shows as incomplete history rather than silently short ranges."""
    now = time.time()
    try:
        n = analysis.store_episodes(conn, now)
        conn.commit()
        state = {"last_ok": now, "last_error": None, "since": None, "stored": n}
    except Exception as e:  # noqa: BLE001 - background, best effort; retried next run
        try:
            conn.rollback()
        except sqlite3.Error:
            pass
        log(f"episodes: couldn't store slowdowns and outages ({e!r}) - retrying in 5 minutes")
        try:  # the same failure (a locked database) can hit this read: it must not end the loop
            prev = store.get_state(conn, analysis.EPISODES_STORE_KEY) or {}
        except sqlite3.Error:
            prev = {}
        prev = prev if isinstance(prev, dict) else {}
        state = {"last_ok": prev.get("last_ok"), "last_error": f"saving slowdowns and outages failed: "
                 f"{type(e).__name__}", "since": prev.get("since") or now}
    _fail_safe("episodes", conn, lambda: store.set_state(conn, analysis.EPISODES_STORE_KEY, state))


def spike_hours_loop(stop):
    """Fill spike_hours in the background, a few hours at a time, so no request ever computes
    them. Best effort: any error is logged and retried next time, never stopping the loop."""
    conn = store.db()
    skip = set()  # hours found unmonitored, or whose processing failed
    try:
        stop.wait(60)
        while not stop.is_set():
            try:
                analysis.fill_spike_hours(conn, time.time(), skip=skip)
            except Exception as e:  # noqa: BLE001 - background, best effort
                try:
                    conn.rollback()
                except sqlite3.Error:
                    pass
                log(f"spike hours: {e!r} - that hour is skipped, the rest carry on")
            store_episodes_once(conn)
            skip = {h for h in skip if h >= time.time() - 3 * 86400}  # bounded: older hours age out
            stop.wait(SPIKE_HOURS_INTERVAL_S)
    finally:
        conn.close()


# --------------------------------------------------------------------------- WiFi radios
_NETSH_SSID = re.compile(r"^SSID \d+ : ?(.*)$")
_NETSH_KV = re.compile(r"^\s*(BSSID \d+|Signal|Band|Channel|Connected Stations|Channel Utilization)\s*:\s*(.*)$")


def _trigger_wifi_scan():
    """Ask Windows for a fresh scan; otherwise netsh can show a stale cached list."""
    import ctypes
    import ctypes.wintypes as wt

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wt.DWORD), ("Data2", wt.WORD), ("Data3", wt.WORD), ("Data4", ctypes.c_ubyte * 8)]

    class IfInfo(ctypes.Structure):
        _fields_ = [("guid", GUID), ("desc", ctypes.c_wchar * 256), ("state", wt.DWORD)]

    class IfList(ctypes.Structure):
        _fields_ = [("n", wt.DWORD), ("i", wt.DWORD), ("items", IfInfo * 1)]

    w = ctypes.windll.wlanapi
    h, ver, lst = wt.HANDLE(), wt.DWORD(), ctypes.POINTER(IfList)()
    if w.WlanOpenHandle(2, None, ctypes.byref(ver), ctypes.byref(h)) != 0:
        return False
    try:
        if w.WlanEnumInterfaces(h, None, ctypes.byref(lst)) != 0 or not lst.contents.n:
            return False
        n = lst.contents.n
        items = ctypes.cast(ctypes.byref(lst.contents.items), ctypes.POINTER(IfInfo * n)).contents
        for it in items:
            w.WlanScan(h, ctypes.byref(it.guid), None, None, None)
        w.WlanFreeMemory(lst)
        return True
    finally:
        w.WlanCloseHandle(h, None)


def read_wifi():
    """Parse `netsh wlan show networks mode=bssid` into one dict per radio (BSSID)."""
    try:
        out = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"],
                             capture_output=True, text=True, timeout=15).stdout
    except Exception:
        return []
    radios, ssid, cur = [], None, None
    for line in out.splitlines():
        m = _NETSH_SSID.match(line)
        if m:
            ssid = m.group(1).strip()
            continue
        m = _NETSH_KV.match(line)
        if not m:
            continue
        k, v = m.group(1), m.group(2).strip()
        if k.startswith("BSSID"):
            cur = {"ssid": ssid, "bssid": v.lower(), "band": None, "channel": None,
                   "signal": None, "util": None, "stations": None}
            radios.append(cur)
        elif cur is None:
            continue
        elif k == "Signal":
            cur["signal"] = int(v.rstrip("%")) if v.rstrip("%").isdigit() else None
        elif k == "Band":
            cur["band"] = v
        elif k == "Channel":
            cur["channel"] = int(v) if v.isdigit() else None
        elif k == "Connected Stations":
            cur["stations"] = int(v) if v.isdigit() else None
        elif k == "Channel Utilization":
            pm = re.search(r"\((\d+)\s*%\)", v)  # e.g. "113 (44 %)"
            cur["util"] = int(pm.group(1)) if pm else None
    return radios


def wifi_loop(stop):
    """Log every radio in range. Radios broadcast by our own devices (matched by MAC) also
    raise events on a channel change or when they vanish, e.g. a DFS radar move."""
    interval = float(CFG["wifi_scan_interval_s"])
    conn = store.db()
    tracker = WifiTracker()
    while not stop.is_set():
        _trigger_wifi_scan()
        stop.wait(5)  # scan takes ~4 s
        radios = read_wifi()
        now = time.time()
        mac_name = {r[2]: r[8] for r in sorted(device_rows(conn), key=lambda r: (r[5] or 0, r[7] or 0)) if r[2]}
        macs = list(mac_name)
        ours = []
        for r in radios:
            owner = net.radio_owner(r["bssid"], macs)
            if owner:
                ours.append((r, owner, mac_name.get(owner, owner)))
        events = tracker.update(ours)

        def write():
            for r in radios:
                conn.execute("INSERT INTO wifi VALUES (?,?,?,?,?,?,?,?)",
                             (now, r["ssid"], r["bssid"], r["band"], r["channel"],
                              r["signal"], r["util"], r["stations"]))
            for kind, detail in events:
                store.add_event(conn, kind, detail)

        _fail_safe("wifi", conn, write)
        stop.wait(max(1, interval - 5))


def is_dfs(channel):
    """5 GHz channels 52-144 are shared with radar: the radio must leave them if radar appears."""
    return channel is not None and 52 <= channel <= 144


class WifiTracker:
    """Turns successive scans of our own access points' radios into events, per device rather
    than per radio: Windows scans routinely miss a hidden network for a scan or two, so a single
    radio vanishing means nothing, but all of a device's radios vanishing means it went off air."""

    MISSES_FOR_LOST = 2      # consecutive scans with none of the device's radios
    MIN_SIGNAL_FOR_LOST = 60  # weak (distant) devices drop out of scans routinely

    def __init__(self):
        self.channel = {}   # (owner mac, band) -> channel
        self.names = {}     # owner mac -> display name
        self.signal = {}    # owner mac -> strongest signal last seen
        self.missing = {}   # owner mac -> consecutive scans unseen
        self.lost = set()

    def update(self, ours):
        """ours: [(radio dict, owner mac, owner name)] from one scan -> [(event kind, detail)]."""
        events, strongest, by_band = [], {}, {}
        for r, owner, name in ours:
            self.names[owner] = name
            strongest[owner] = max(strongest.get(owner, 0), r["signal"] or 0)
            if r["channel"] is not None:
                # prefer a visible (named) network's channel - hidden backhaul follows it - and
                # pick deterministically (lowest) if one device has several, whatever scan order
                key, rank = (owner, r["band"]), (0 if r["ssid"] else 1, r["channel"])
                if key not in by_band or rank < by_band[key]:
                    by_band[key] = rank
        by_band = {k: rank[1] for k, rank in by_band.items()}
        for (owner, band), ch in by_band.items():
            prev = self.channel.get((owner, band))
            if prev is not None and prev != ch:
                note = " (radar-shared DFS channel)" if is_dfs(ch) else ""
                events.append((EV_WIFI_CHANNEL, f"WiFi {self.names[owner]} {band} moved channel {prev} -> {ch}{note}"))
            self.channel[(owner, band)] = ch
        seen = set(strongest)
        self.signal.update(strongest)
        for owner in seen:
            if owner in self.lost:
                self.lost.discard(owner)
                events.append((EV_WIFI_BACK, f"WiFi {self.names[owner]} is back on the air"))
            self.missing[owner] = 0
        for owner in list(self.names):
            if owner in seen or owner in self.lost:
                continue
            self.missing[owner] = self.missing.get(owner, 0) + 1
            if self.missing[owner] == self.MISSES_FOR_LOST and self.signal.get(owner, 0) >= self.MIN_SIGNAL_FOR_LOST:
                self.lost.add(owner)
                events.append((EV_WIFI_LOST, f"WiFi {self.names[owner]} went off the air (none of its radios seen)"))
        return events


# --------------------------------------------------------------------------- router: per-device traffic
ROUTER_MIN_REFRESH_GAP_S = 10   # "Refresh now" pressed repeatedly can't hammer the router
ROUTER_MAX_GAP_S = 6 * 3600     # after a longer gap, re-baseline rather than book hours of
                                # traffic into one reading
ROUTER_RETRY_S = 600            # after a failed reading: the router is down, rebooting or the
                                # password changed - back off (also avoids its login lockout)
ROUTER_STATUS_EVERY_S = 60      # the router's health (temperature, uptime): once a minute is
                                # plenty, even while live mode reads traffic every few seconds


def _span(s):
    """Seconds as a short duration: '3 d 4 h', '2 h 18 m', '45 m'."""
    d, h, m = int(s // 86400), int(s % 86400 // 3600), int(s % 3600 // 60)
    return f"{d} d {h} h" if d else f"{h} h {m} m" if h else f"{m} m"


def note_public_ip(conn, ip, now):
    """The internet address as the router reports it (over UPnP, or the GL.iNet's own API): a
    change is an event - on PPPoE it means the line reconnected. One record for both sources,
    so a router that offers both doesn't log each change twice."""
    if not ip:
        return
    before = store.get_state(conn, UPNP_PUBLIC_IP_KEY)
    if before and before != ip:
        store.add_event(conn, "public_ip", f"The internet address changed from {before} to {ip} (as the router "
                                           "reports it) - the line reconnected", now)
    store.set_state(conn, UPNP_PUBLIC_IP_KEY, ip)


ROUTER_SECURITY_EVERY_S = 3600   # what can reach the home from the internet changes rarely


def _read_router_security(conn, rt, now):
    """The router's ways in from the internet and its firmware (#131), hourly; a firmware
    change is an event. Optional like the health reading."""
    try:
        sec = rt.security()
    except (router.RouterError, ValueError, OSError):
        return
    if all(v is None for v in sec.values()):
        return

    def write():
        prev = store.get_state(conn, router.SECURITY_STATE_KEY)
        prev_fw = (prev.get("firmware") if isinstance(prev, dict) else None) or None
        before = (prev_fw or {}).get("version")
        now_fw = (sec.get("firmware") or {}).get("version")
        if before and now_fw and before != now_fw:
            store.add_event(conn, EV_ROUTER, f"The router's firmware changed from {before} to {now_fw}", now)
        # a reading whose firmware call failed keeps the last known one, so an update landing
        # meanwhile still shows as a change at the next good reading (#133)
        store.set_state(conn, router.SECURITY_STATE_KEY,
                        {**sec, "firmware": sec.get("firmware") or prev_fw, "ts": now})
    _fail_safe("router", conn, write)


def _read_router_link(conn, rt, now):
    """The internet connection (PPPoE/DHCP, up, its address) and the traffic shaping, as the
    router reports them (#122). Optional like the health reading: a firmware without them, or a
    failed call, changes nothing."""
    try:
        link = rt.link()
    except (router.RouterError, ValueError, OSError):
        return
    if not link.get("wan") and not link.get("sqm"):
        return

    def write():
        store.set_state(conn, router.LINK_STATE_KEY, {**link, "ts": now})
        note_public_ip(conn, (link.get("wan") or {}).get("ip"), now)
    _fail_safe("router", conn, write)


def _read_router_status(conn, rt, now):
    """Record the router's health and notice when it restarted. Optional: a firmware that
    doesn't offer it, or a failed call, leaves the traffic reading untouched."""
    try:
        st = rt.status()
    except (router.RouterError, ValueError, OSError):
        return
    prev = store.get_state(conn, router.STATUS_STATE_KEY)

    def write():
        store.add_router_stats(conn, now, st)
        if router.restarted(prev, prev.get("ts", 0) if prev else 0, st, now):
            # dated when it came back up, not when Hearth noticed
            store.add_event(conn, EV_ROUTER, f"The router restarted (it had been running {_span(prev['uptime_s'])} "
                                             "at the reading before)", ts=now - st["uptime_s"])
        # a reading without a usable uptime can't be compared, so it must not replace the last
        # one that can - otherwise a restart falling in that gap would go unlogged
        if st.get("uptime_s") is not None or not prev:
            store.set_state(conn, router.STATUS_STATE_KEY, {**st, "ts": now})
    _fail_safe("router", conn, write)


CREDENTIALS_RECHECK_S = 15   # an unconfigured router or mesh reader looks for a password this often


def router_loop(stop):
    """Every minute (configurable), or when the dashboard asks: read the router's client list
    and record how many bytes each device moved since the last reading. Off - silently idle -
    when there's no credentials file. Failures are logged once, retried every 10 minutes
    (counters are cumulative, so nothing is lost meanwhile) and recovery is logged."""
    path = router.credentials_path()
    if not router.has_password(path, router.PASSWORD_KEY):
        log(f"router: no {router.PASSWORD_KEY} in {path} - per-device traffic off until one is added")
        _report_unconfigured(sources.ROUTER, "no router login set up")
        # the Setup panel can add one (#105): look again until it's there, no restart needed
        while not router.has_password(path, router.PASSWORD_KEY):
            if stop.wait(CREDENTIALS_RECHECK_S):
                return
        log("router: a password was added - reading the router")
    conn = store.db()
    prev = {m: tuple(v) for m, v in (store.get_state(conn, "router_totals", {}) or {}).items()}
    prev_ts = store.get_state(conn, "router_totals_ts", 0) or 0
    rt, failing, announced, requested, status_ts, security_ts = None, False, None, False, 0.0, 0.0
    since, last_reason = 0.0, None
    while not stop.is_set():
        router.REFRESH.clear()  # this reading answers any press so far
        try:
            gw, _, _ = network_settings()
            if rt is None or rt.host != gw:  # first run, or the router changed
                rt = router.GlinetRouter(gw, path)
            clients = rt.clients()
        except (router.RouterError, ValueError, OSError) as e:
            clients = None
            reason = str(e)[:200]
            if not failing or reason != last_reason:  # log and show it again when the cause changes
                log(f"router: can't read per-device traffic ({reason}) - retrying every "
                    f"{ROUTER_RETRY_S // 60} minutes")
                since = since if failing else time.time()  # the outage keeps its start time
                failing, last_reason = True, reason
                # shown on the dashboard; RouterError messages never carry secrets
                err = {"since": since, "error": reason}
                _fail_safe("router", conn, lambda: store.set_state(conn, router.ERROR_STATE_KEY, err))
            _fail_safe("router", conn, lambda: sources.report_error(conn, sources.ROUTER, reason))
        if clients is not None:
            _fail_safe("router", conn, lambda: sources.report_ok(conn, sources.ROUTER, {"host": rt.host}))
            if failing or rt.host != announced:  # started, recovered, or a new router
                log(f"router: reading per-device traffic from {rt.host} every {router.poll_interval_s():.0f}s")
                failing, announced = False, rt.host
                _fail_safe("router", conn, lambda: store.set_state(conn, router.ERROR_STATE_KEY, None))
            now = time.time()
            cur = {c["mac"]: (c["rx_total"], c["tx_total"]) for c in clients}
            dur = now - prev_ts
            deltas = router.counter_deltas(prev, cur) if 0 < dur <= ROUTER_MAX_GAP_S else {}

            def write():
                store.save_router_clients(conn, now, clients)
                store.add_usage(conn, now, dur, deltas)
                store.set_state(conn, "router_totals", cur)
                store.set_state(conn, "router_totals_ts", now)
            _fail_safe("router", conn, write)
            prev, prev_ts = cur, now
            if now - status_ts >= ROUTER_STATUS_EVERY_S:
                status_ts = now
                _read_router_status(conn, rt, now)
                _read_router_link(conn, rt, now)
            if now - security_ts >= ROUTER_SECURITY_EVERY_S:
                security_ts = now
                _read_router_security(conn, rt, now)
            if requested:
                analysis.clear_cache()  # the dashboard asked for this reading: show it now
        if failing:
            # "Refresh now" can't cut the back-off short: retrying a refused login every few
            # seconds would trip the router's lockout - and neither does live mode
            requested = False
            if stop.wait(ROUTER_RETRY_S):
                return
            continue
        if live.active():
            # someone's watching: read again in a few seconds (our own pace, not a button)
            requested = False
            if stop.wait(live.ROUTER_INTERVAL_S):
                return
            continue
        # background: a minimum gap first (a press during it is remembered), then sleep until
        # the next reading is due, "Refresh now" is pressed, or someone opens the dashboard
        if stop.wait(ROUTER_MIN_REFRESH_GAP_S):
            return
        woke = wait_either(stop, router.REFRESH, router.poll_interval_s() - ROUTER_MIN_REFRESH_GAP_S,
                           wake_if=live.active)
        if woke == "stop":
            return
        requested = woke == "refresh"


def wait_either(stop, event, timeout, step=1.0, wake_if=None):
    """Sleep until `event` is set ("refresh"), `stop` is set ("stop"), wake_if() turns true
    ("live") or the time is up (None). Checks at least every `step` seconds, so shutting down
    or a viewer arriving never waits a whole interval."""
    deadline = time.monotonic() + max(0.0, timeout)
    while True:
        if stop.is_set():
            return "stop"
        if wake_if and wake_if():
            return "live"
        left = deadline - time.monotonic()
        if left <= 0:
            return None
        if event.wait(min(step, left)):
            return "refresh"


# --------------------------------------------------------------------------- mesh layout (Deco)
MESH_AUTH_RETRY_S = 6 * 3600  # after a refused login: some firmware locks out repeated failures


def mesh_changes(old, new):
    """Event lines for mesh nodes that dropped off, came back, or changed how they connect."""
    before = {n["mac"]: n for n in (old or {}).get("nodes", [])}
    out = []
    for n in new.get("nodes", []):
        o, name = before.get(n["mac"]), n.get("name") or n["mac"]
        if o is None:
            continue
        if o.get("online") and not n.get("online"):
            out.append(f"Mesh node {name} dropped off the mesh")
        elif n.get("online") and not o.get("online"):
            out.append(f"Mesh node {name} is back on the mesh")
        if n.get("backhaul") != o.get("backhaul") and n.get("role") != "main":
            out.append(f"Mesh node {name} now connects {n.get('backhaul')} (was {o.get('backhaul')})")
        # a firmware update (#131); a reading without one (older snapshots) isn't a change
        if n.get("firmware") and o.get("firmware") and n["firmware"] != o["firmware"]:
            out.append(f"Mesh node {name}'s firmware changed from {o['firmware']} to {n['firmware']}")
    gone = set(before) - {n["mac"] for n in new.get("nodes", [])}
    out += [f"Mesh node {before[m].get('name') or m} is no longer listed" for m in gone]
    return out


CERT_EVENT_EVERY_S = 6 * 3600  # a change waiting for you is logged at most this often per unit


def norm_mac(mac):
    """aa:bb:cc:dd:ee:ff, whatever the source wrote (or None)."""
    return str(mac).replace("-", ":").lower() if mac else None


def safe_arp():
    """This computer's ARP table, or {} if it can't be read (then nothing is auto-accepted)."""
    try:
        return net.read_arp()
    except Exception:  # an unreadable neighbour table must never abort a mesh reading
        return {}


def mesh_write(conn, fn):
    """Run fn as one write transaction for the mesh's trust state, and commit. BEGIN IMMEDIATE
    takes the write lock before fn reads anything, so a trust you confirm at the same moment
    (another connection) can't be lost between this read and this write. A database error or
    damaged pins/identity is logged and rolled back - a failed write, retried next reading -
    never an exception that ends the mesh reader. Returns True if committed."""
    try:
        if conn.in_transaction:
            conn.commit()
        conn.execute("BEGIN IMMEDIATE")
        fn()
        conn.commit()
        return True
    except (sqlite3.Error, mesh.PinsDamaged) as e:
        log(f"mesh: {e} - will retry")
        try:
            conn.rollback()
        except sqlite3.Error:
            pass  # the connection is unusable; the next reading opens its transaction afresh
        return False


def _ask(conn, host, old, new, why, kind, keys, now):
    """Record a change for you to confirm on the dashboard (inside a mesh_write). One event per
    change, but at most one per unit every CERT_EVENT_EVERY_S - kept apart from the pending row,
    so a successful reading (which clears the banner) doesn't reset it."""
    pending = store.get_state(conn, mesh.CERT_PENDING_KEY) or {}
    if pending.get("host") == host and pending.get("new") == new and pending.get("kind", "cert") == kind \
            and pending.get("keys") == keys:
        return  # already waiting for you
    logged = store.get_state(conn, mesh.CERT_EVENTS_KEY) or {}
    logged = logged if isinstance(logged, dict) else {}
    last = logged.get(host)
    if not isinstance(last, (int, float)) or not math.isfinite(last) or now - last >= CERT_EVENT_EVERY_S:
        if kind == "keys":
            text = (f"The mesh's main unit ({host}) offered different login keys - Hearth sent it nothing, "
                    "including your password. Confirm it on the dashboard if you expected this (a reset or "
                    "replaced unit)")
        else:
            text = (f"The mesh's main unit ({host}) presented a new security certificate and Hearth didn't accept "
                    f"it by itself: {why}. Confirm it on the dashboard to keep reading the mesh")
        store.add_event(conn, EV_MESH, text, now)
        store.set_state(conn, mesh.CERT_EVENTS_KEY, {**logged, host: now})
    store.set_state(conn, mesh.CERT_PENDING_KEY, {"host": host, "old": old, "new": new, "since": now,
                                                  "kind": kind, "reason": why, "keys": keys})


def _log_accepted(conn, host, mac, now):
    """A certificate change accepted without asking: logged once a day, the first time, with a
    count of the previous day's changes when there was more than one (inside a mesh_write)."""
    day = time.strftime("%Y-%m-%d", time.localtime(now))
    rec = store.get_state(conn, mesh.CERT_LOG_KEY) or {}
    count = rec.get("count") if isinstance(rec, dict) else None
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        rec, count = {}, 0   # unreadable: only the event count is affected, never what's trusted
    if rec.get("day") != day:
        before = f" It changed {count} times on {rec['day']}." if count > 1 and isinstance(rec.get("day"), str) else ""
        store.add_event(conn, EV_MESH, f"The mesh's main unit ({host}) changed its security certificate; its login "
                                       f"keys and MAC ({mac}) are unchanged, so Hearth accepted it. Further changes "
                                       f"today are accepted without another entry.{before}", now)
        count = 0
    store.set_state(conn, mesh.CERT_LOG_KEY, {"day": day, "count": count + 1})


def note_cert_change(conn, e, mac_before=None, mac_after=None, keys=None):
    """A unit presented a different certificate. Only the address Hearth reads the mesh from
    counts: a satellite's own certificate was never trusted, so there's nothing to re-trust.

    TP-Link main units change certificate every few hours while running (seen on a BE9300; the
    observation is in docs/superpowers/specs/deco-identity-observation.md), but their two login
    keys - which protect the password - stay the same. So the new certificate is accepted
    without asking when mesh.cert_decision agrees: same keys (keys: what the unit offered with
    the new certificate, read without sending anything, or None if that failed), and its
    address mapped to the recorded MAC before and after the attempt. Otherwise it waits for
    you, with the reason. Several changes between two readings are only ever seen as the
    latest one. Everything is decided inside one write transaction, so a trust you confirmed
    meanwhile is seen, never overwritten."""
    accepted = False
    before, after = norm_mac(mac_before), norm_mac(mac_after)

    def write():
        nonlocal accepted
        if e.host != store.get_state(conn, "mesh_host"):
            return
        pins = mesh.read_pins(conn)
        if pins.get(e.host) == e.new:
            return  # already trusted (you confirmed it while this reading was running)
        ident = mesh.read_identity(conn)
        now = time.time()
        verdict, why = mesh.cert_decision(ident, keys, before, after, mesh.auto_trust_enabled())
        if verdict == "accept":
            store.set_state(conn, mesh.PINS_STATE_KEY, {**pins, e.host: e.new})
            if (store.get_state(conn, mesh.CERT_PENDING_KEY) or {}).get("host") == e.host:
                store.set_state(conn, mesh.CERT_PENDING_KEY, None)  # only this unit's banner
            _log_accepted(conn, e.host, ident["mac"], now)
            accepted = True
            return
        # new keys with the new certificate: a keys change, worded as one on the dashboard (and
        # only a keys change records new keys when you confirm it)
        new_keys = bool(ident and keys and any(keys.get(k) != ident[k] for k in mesh.KEY_NAMES))
        _ask(conn, e.host, e.old, e.new, why, "keys" if new_keys else "cert", keys, now)
    if mesh_write(conn, write) and accepted:
        log(f"mesh: {e.host} has a new certificate; same login keys and MAC - accepted")
        mesh.TRUSTED.set()  # read again straight away rather than after the back-off


def note_keys_change(conn, e):
    """The main unit offered login keys other than the recorded ones (mesh.KeysChanged): always
    for you to confirm - new keys are exactly what an impostor would bring."""
    if not e.cert:
        return  # no certificate to pin with them: nothing you could confirm (the transport sets one)

    def write():
        if e.host != store.get_state(conn, "mesh_host"):
            return
        ident = mesh.read_identity(conn)
        if ident and all(ident[k] == e.new[k] for k in mesh.KEY_NAMES):
            return  # already trusted (you confirmed it while this reading was running)
        _ask(conn, e.host, e.cert, e.cert, "its login keys changed", "keys", e.new, time.time())
    mesh_write(conn, write)


def probe_keys(host, cert, path):
    """The login keys a unit offers over a connection that must present `cert` (the new
    certificate just seen), or None if that can't be read. Sends nothing secret."""
    try:
        return mesh.Deco(host, path, {host: cert}).read_keys()
    except (router.RouterError, ValueError):   # MeshError is a RouterError
        return None


def remember_identity(conn, deco, pins, anchor, now):
    """After a successful reading, inside its mesh_write (pins is edited in place):
    - the first time (or the first reading after an upgrade), record the main unit's identity:
      the login keys this session used, and the MAC its address has (anchor, from the ARP table);
    - fill in the MAC if it's missing (Hearth re-anchors it after you confirm a change);
    - follow the unit to a new address, dropping its old address's pin so that address isn't
      tried first, with its 15 s timeout, on every later start.
    The recorded MAC is only replaced by your confirmation, never by a reading. Keys that differ
    from the record mean you confirmed new ones during this reading: yours stand."""
    if not deco.keys:
        return
    ident = mesh.read_identity(conn)
    if ident is None:
        ident = {"host": deco.host, **deco.keys, "mac": anchor, "since": now}
    elif any(ident[k] != deco.keys[k] for k in mesh.KEY_NAMES):
        return
    else:
        ident = dict(ident)
        if ident["host"] != deco.host:
            pins.pop(ident["host"], None)
            ident["host"] = deco.host
        if not ident.get("mac") and anchor:
            ident["mac"] = anchor
    if ident != mesh.read_identity(conn):
        store.set_state(conn, mesh.IDENTITY_STATE_KEY, ident)


UPNP_INTERVAL_S = 60            # read the router's UPnP counters this often
UPNP_DISCOVER_S = 1800          # look for a UPnP gateway again this often while none answers
UPNP_FORGET_S = 7 * 86400       # gone this long after working: assume it was turned off on purpose
UPNP_PUBLIC_IP_KEY = "upnp_public_ip"


def upnp_enabled():
    v = CFG.get("upnp", True)
    return v is not False and str(v).lower() not in ("false", "0", "no", "off")


def upnp_absent(conn, reason, now):
    """No usable UPnP gateway right now. Never found: not set up. Found before and lost (a
    restart, UPnP switched off, a new router): a failure - until UPNP_FORGET_S after it last
    worked, when Hearth assumes it was turned off on purpose."""
    st = sources.read(conn, sources.UPNP) or {}
    last_ok = st.get("last_ok")
    if isinstance(last_ok, (int, float)) and now - last_ok < UPNP_FORGET_S:
        sources.report_error(conn, sources.UPNP, reason, now)
    else:
        sources.report_unconfigured(conn, sources.UPNP, reason)


def record_upnp(conn, reading, prev, now):
    """Store one UPnP reading: bytes moved since the previous one (32-bit wraps handled, a
    restart or a long gap books nothing), a public IP change as an event, the source's state."""
    if prev is not None and 0 < now - prev[0] <= ROUTER_MAX_GAP_S:
        dur, p = now - prev[0], prev[1]
        rx = upnp.counter_delta(p["rx_total"], reading["rx_total"], dur, reading.get("down_bps"))
        tx = upnp.counter_delta(p["tx_total"], reading["tx_total"], dur, reading.get("up_bps"))
        if rx is not None and tx is not None:
            conn.execute("INSERT INTO traffic_wan VALUES (?,?,?,?)", (now, rx, tx, dur))
    note_public_ip(conn, reading.get("public_ip"), now)
    sources.report_ok(conn, sources.UPNP, {k: reading.get(k) for k in ("link_up", "down_bps", "up_bps", "public_ip",
                                                                       "connected", "uptime_s")}, now)


def upnp_loop(stop):
    """Every minute, read the router's UPnP gateway if it has one (upnp.py: read-only, pinned
    to the gateway's address). Looked for at start; then, while none answers, every 30 minutes
    if it never has - or every minute if it worked before (a router rebooting, back in a minute
    or two, mustn't show as failing for half an hour), until UPNP_FORGET_S after it last worked.
    A new router address, a failed read or a failed description fetch looks again straight away."""
    if not upnp_enabled():
        _report_unconfigured(sources.UPNP, "turned off in config.json (upnp: false)")
        stop.wait()
        return
    conn = store.db()
    gw_addr, dev, prev, last_look, looking, last_ok, found = None, None, None, 0.0, False, None, False
    try:
        while not stop.is_set():
            now = time.time()
            try:
                gw = analysis._gateway_ip(conn)
                if gw != gw_addr:
                    # the first router this run: carry on from when UPnP last worked (saved), so a
                    # Hearth restart doesn't fall back to the slow search; a new router: start afresh
                    saved = (sources.read(conn, sources.UPNP) or {}).get("last_ok") if gw_addr is None else None
                    last_ok = saved if isinstance(saved, (int, float)) else None
                    gw_addr, dev, prev, last_look, found = gw, None, None, 0.0, False
                lost = last_ok is not None and now - last_ok < UPNP_FORGET_S
                # it worked before, or it answers but can't be read: look every turn; never answered: slowly
                every = UPNP_INTERVAL_S if lost or found else UPNP_DISCOVER_S
                if dev is None and gw and now - last_look >= every:
                    last_look, looking = now, True
                    loc = upnp.discover(gw)
                    looking = False                  # only the search itself keeps the cadence
                    dev = upnp.Gateway(gw, loc) if loc else None
                    found = found or dev is not None
                if dev is None:
                    _fail_safe("upnp", conn, lambda: upnp_absent(conn, "the router doesn't answer UPnP", now))
                else:
                    reading = dev.read()
                    now = time.time()                # stamped when read: up to five calls took time
                    p = prev
                    if _fail_safe("upnp", conn, lambda: record_upnp(conn, reading, p, now)):
                        prev, last_ok = (now, reading), now
            except Exception as e:  # noqa: BLE001 - a bad reply, a locked database: never end the reader
                dev = None
                if not looking:                      # a read that failed: look again next time; a
                    last_look = 0.0                  # search that failed keeps its 30-minute cadence
                looking = False
                if isinstance(e, upnp.UpnpError):
                    reason = str(e)[:200]
                else:
                    reason = f"couldn't read UPnP ({type(e).__name__})"
                    log(f"upnp: {e!r} - will retry")
                try:
                    conn.rollback()
                except sqlite3.Error:
                    pass
                if found:   # the router answers UPnP but can't be read: set up, and failing
                    _fail_safe("upnp", conn, lambda: sources.report_error(conn, sources.UPNP, reason, time.time()))
                else:
                    _fail_safe("upnp", conn, lambda: upnp_absent(conn, reason, time.time()))
            stop.wait(UPNP_INTERVAL_S)
    finally:
        conn.close()


def _report_unconfigured(name, why):
    """A reader that isn't set up says so once at start (its own short-lived connection)."""
    conn = store.db()
    try:
        _fail_safe(name, conn, lambda: sources.report_unconfigured(conn, name, why))
    finally:
        conn.close()


PLACE_INSERT = "INSERT OR REPLACE INTO device_places (ts, device, node, how) VALUES (?,?,?,?)"


def record_places(conn, places, now, candidates):
    """Record where devices are (places: {device: (node, how)} for every online device), a row
    only when a device's place changes - and only once a change has held for two readings in a
    row (candidates holds the first reading of each change, in memory), so a device on a timing
    boundary, flickering in and out of the mesh's list, or roaming between two units doesn't
    write a row every reading. A device's first place is written at once. A different reading
    while a change is pending replaces it and starts the count again; a device that isn't online
    drops its pending change. Rows carry the time the change was first seen.
    Returns the pending changes after this reading, leaving `candidates` untouched, so the
    caller adopts them only if the rows were committed."""
    candidates = dict(candidates)
    latest = {d: (n, h) for d, n, h in conn.execute(
        """SELECT device, node, how FROM device_places p
           WHERE ts = (SELECT MAX(ts) FROM device_places WHERE device = p.device)""")}
    for device, place in places.items():
        cur = latest.get(device)
        if cur is None:
            conn.execute(PLACE_INSERT, (now, device, *place))
            candidates.pop(device, None)
        elif cur == place:
            candidates.pop(device, None)      # back where it was: nothing pending
        else:
            pending = candidates.get(device)
            if pending and pending[:2] == place:
                conn.execute(PLACE_INSERT, (pending[2], device, *place))
                candidates.pop(device)
            else:
                candidates[device] = (*place, now)   # new, or different from the pending one
    for device in [d for d in candidates if d not in places]:
        candidates.pop(device)                # not online at this reading
    return candidates


def mesh_loop(stop):
    """Every 5 minutes (configurable), or on "Refresh now": read the mesh layout from the main
    unit. Off when the credentials file has no DECO_PASSWORD. Failures log once and back off."""
    path = router.credentials_path()
    if not router.has_password(path, mesh.PASSWORD_KEY):
        log(f"mesh: no {mesh.PASSWORD_KEY} in {path} - mesh layout off until one is added")
        _report_unconfigured(sources.MESH, f"no {mesh.PASSWORD_KEY} set up")
        while not router.has_password(path, mesh.PASSWORD_KEY):   # the Setup panel can add one (#105)
            if stop.wait(CREDENTIALS_RECHECK_S):
                return
        log("mesh: a password was added - reading the mesh")
    conn = store.db()
    deco, failing, last_reason, since = None, False, None, None
    place_candidates = {}   # device -> (node, how, first seen): a change waiting for its second reading
    while not stop.is_set():
        mesh.REFRESH.clear()
        mesh.TRUSTED.clear()
        snap, err = None, None
        try:
            pins = mesh.read_pins(conn)
            identity = mesh.read_identity(conn)
            if deco:  # a kept session logs in again when it expires: check against today's record
                deco.identity = identity
            hosts = [deco.host] if deco else mesh.find_candidates(conn, pins, net.vendor)
            auto = mesh.auto_trust_enabled()
            for addr in hosts:
                # the ARP table just before this attempt (only needed for auto-trust; one quick read)
                arp_before = safe_arp() if auto else {}
                try:
                    d = deco if deco and deco.host == addr else mesh.Deco(addr, path, pins, identity)
                    snap, deco = d.snapshot(), d
                    break
                except mesh.MeshAuthError as e:
                    err, deco = e, None
                    break  # the password itself is wrong: trying more hosts only adds failed logins
                except (router.RouterError, ValueError) as e:  # MeshError is a RouterError
                    # report the most trusted host's failure (tried first), not the last fallback's
                    err = err or e
                    if isinstance(e, mesh.CertChanged):
                        # the login keys offered with the new certificate (nothing secret is
                        # sent), then the address's MAC in the ARP table after the attempt: with
                        # the one before, it tells the same unit from a different device
                        keys = probe_keys(e.host, e.new, path) if auto else None
                        note_cert_change(conn, e, arp_before.get(e.host),
                                         safe_arp().get(e.host) if auto else None, keys)
                    elif isinstance(e, mesh.KeysChanged):
                        note_keys_change(conn, e)
                    if deco and deco.host == addr:
                        deco = None  # the main unit moved or changed: look again next time
        except Exception as e:  # never let one bad reading (or a locked database) end the loop
            snap, err, deco = None, e, None
        retry = ROUTER_RETRY_S
        if snap is None:
            # two readings in a row means two good ones: a change seen before a failed reading
            # (perhaps hours of them) starts over rather than being confirmed by the next success
            place_candidates = {}
            auth = isinstance(err, mesh.MeshAuthError)
            retry = MESH_AUTH_RETRY_S if auth else ROUTER_RETRY_S  # don't trip a login lockout
            reason = str(err or "no Deco found among known devices")[:200]
            if not failing or reason != last_reason:  # log and show it again when the cause changes
                hint = "" if auth else " (if the main unit's address changed, set mesh_host in config.json)"
                log(f"mesh: can't read the mesh layout ({reason}){hint} - retrying every {retry // 60:.0f} minutes")
                since = since if failing else time.time()
                msg = {"since": since, "error": reason}
                _fail_safe("mesh", conn, lambda: store.set_state(conn, mesh.MESH_ERROR_KEY, msg))
                failing, last_reason = True, reason
            _fail_safe("mesh", conn, lambda: sources.report_error(conn, sources.MESH, reason))
        else:
            now = time.time()
            announce = failing or store.get_state(conn, "mesh_host") != deco.host
            snap.update(ts=now, host=deco.host)
            old = store.get_state(conn, mesh.MESH_STATE_KEY)
            # the unit's MAC, for an identity that has none yet: the ARP read taken before this
            # attempt when there was one, else a fresh read only when it's needed
            needs = not (identity and identity.get("mac"))
            anchor = norm_mac((arp_before if auto else safe_arp() if needs else {}).get(deco.host))

            def write():
                for line in mesh_changes(old, snap):
                    store.add_event(conn, EV_MESH, line, now)
                # backhaul history: a row only when a node's link changes (kind, signal, online),
                # so a steady mesh adds nothing however long it runs
                before = {n["mac"]: n for n in (old or {}).get("nodes", [])}
                for n in snap["nodes"]:
                    o = before.get(n["mac"])
                    if o and all(o.get(k) == n.get(k) for k in ("backhaul", "signal", "online")):
                        continue
                    conn.execute("INSERT INTO mesh_links VALUES (?,?,?,?,?,?)",
                                 (now, n["mac"], n.get("name"), n.get("backhaul"), json.dumps(n.get("signal") or {}),
                                  int(bool(n.get("online")))))
                # backhaul signal and link rates, every reading: the trend is the point
                for n in snap["nodes"]:
                    for band in n.get("bands") or []:
                        rssi, rx, tx = ((n.get(k) or {}).get(band) for k in ("rssi", "rate_rx", "rate_tx"))
                        if rssi is not None or rx is not None:
                            conn.execute("INSERT INTO mesh_backhaul VALUES (?,?,?,?,?,?)",
                                         (now, n["mac"], band, rssi, rx, tx))
                store.set_state(conn, mesh.MESH_STATE_KEY, snap)
                store.set_state(conn, mesh.MESH_ERROR_KEY, None)
                sources.report_ok(conn, sources.MESH, {"host": deco.host})
                store.set_state(conn, mesh.CERT_PENDING_KEY, None)  # read fine: nothing left to confirm
                store.set_state(conn, "mesh_host", deco.host)
                # re-read inside this transaction: a trust you confirmed during this reading must
                # not be overwritten
                current = mesh.read_pins(conn)
                if deco.new_pin:  # first successful contact: from now on this certificate only
                    current[deco.host] = deco.new_pin
                remember_identity(conn, deco, current, anchor, now)
                store.set_state(conn, mesh.PINS_STATE_KEY, current)
            # only a saved reading counts: then the error row is cleared, recovery is logged and a
            # new pin is trusted in memory. If the write failed (mesh_write logged it) the state
            # stays as it was and the next reading tries again
            if mesh_write(conn, write):
                if announce:
                    log(f"mesh: reading the mesh layout from {deco.host} every {mesh.poll_interval_s():.0f}s")
                failing = False
                if deco.new_pin:
                    deco.pin, deco.new_pin = deco.new_pin, None
            analysis.clear_cache()
            try:  # where each device is now, as the map shows it - recorded when it changes
                places, pending = analysis.places_now(analysis.mesh_view(conn, 60)), {}
                ok = _fail_safe("places", conn, lambda: pending.update(record_places(conn, places, now, place_candidates)))
                # adopted only once the rows are committed; a failed record isn't a good reading either,
                # so whatever was pending starts over (two good readings in a row, every time)
                place_candidates = pending if ok else {}
            except Exception as e:  # noqa: BLE001 - never let the record end the mesh reader
                place_candidates = {}
                log(f"places: couldn't record where devices are ({e!r})")
        if stop.wait(ROUTER_MIN_REFRESH_GAP_S):
            return
        if failing:  # "Refresh now" can't cut the back-off short - but confirming a certificate can
            if wait_either(stop, mesh.TRUSTED, max(0, retry - ROUTER_MIN_REFRESH_GAP_S)) == "stop":
                return
        elif wait_either(stop, mesh.REFRESH, mesh.poll_interval_s() - ROUTER_MIN_REFRESH_GAP_S) == "stop":
            return


# --------------------------------------------------------------------------- this machine's health
HOST_INTERVAL_S = 60
HOST_PROCS_EVERY = 5   # biggest programs every 5th sample (5 minutes)


HOST_POOL_EVERY = 60          # stored samples (minutes) between readings of the kernel pool by driver
POOL_HISTORY_S = 7 * 86400
POOL_OWNERS_TTL_S = 86400     # driver files are looked up again after a day (an update may move a tag)


def record_pool_tags(conn, now, tags, pool_total, owners_of=host.tag_owners):
    """Keep a week of hourly readings of the biggest non-paged pool tags; judge which only
    climb (host.leaks, with limits for drivers); and, while the pool is over the warning line,
    find which driver holds the biggest and the growing ones - looked up once a day, a few
    tenths of a second (#127)."""
    hist = store.get_state(conn, host.POOL_HISTORY_KEY) or {}
    hist = {t: [p for p in pts if isinstance(p, list) and len(p) == 2 and p[0] >= now - POOL_HISTORY_S]
            for t, pts in hist.items() if isinstance(pts, list)}
    for t, (size, _live) in tags.items():
        hist.setdefault(t, []).append([now, size])
    hist = {t: pts for t, pts in hist.items() if pts and (t in tags or pts[-1][0] >= now - 86400)}
    store.set_state(conn, host.POOL_HISTORY_KEY, hist)
    found = host.leaks(hist, min_growth=host.POOL_LEAK_MIN_GROWTH)
    store.set_state(conn, host.POOL_LEAKS_KEY, [[t, a, b, hist[t][-1][0] - hist[t][0][0]] for t, a, b in found])
    if (pool_total or 0) < host.NONPAGED_WARN:
        return
    want = [t for t, _ in sorted(tags.items(), key=lambda kv: -kv[1][0])[:3]] + [t for t, _a, _b in found]
    cached = store.get_state(conn, host.POOL_OWNERS_KEY)
    cached = cached if isinstance(cached, dict) else {}
    known = cached.get("owners") if isinstance(cached.get("owners"), dict) else {}
    fresh = isinstance(cached.get("ts"), (int, float)) and now - cached["ts"] < POOL_OWNERS_TTL_S
    if not fresh:   # all of them again once a day (an update may move a tag)
        store.set_state(conn, host.POOL_OWNERS_KEY, {"ts": now, "owners": owners_of(sorted(set(want)))})
        return
    # within the day only tags never looked up, kept alongside the others - two tags trading
    # places in the top three mustn't mean reading every driver each hour (#128 review)
    missing = sorted({t for t in want if t not in known})
    if missing:
        store.set_state(conn, host.POOL_OWNERS_KEY, {"ts": cached["ts"], "owners": {**known, **owners_of(missing)}})


def host_loop(stop):
    """A sample of this computer's CPU, memory, commit charge, kernel pools and handles every
    minute; its biggest programs every 5 minutes. Windows API calls only - a few milliseconds."""
    reader = host.Reader()
    if not reader.ok:
        log("host: not supported on this system - computer health off")
        stop.wait()
        return
    conn = store.db()
    n, written, unreadable = 0, 0, False
    live_reader = host.Reader()  # its own CPU baseline, so live samples don't skew the stored ones
    was_live = [False]

    def pause(seconds):
        """Wait for the next stored sample; while someone's watching, sample every few seconds
        into memory for the live view. Returns True when it's time to stop."""
        end = time.monotonic() + seconds
        while True:
            left = end - time.monotonic()
            if left <= 0:
                return False
            if stop.wait(min(left, live.HOST_INTERVAL_S)):
                return True
            on = live.active()
            if on and not was_live[0]:
                # live mode just started: forget the old CPU baseline, or the first "live" figure
                # would be an average over however long nobody was looking
                live_reader.reset_cpu()
                live.set_host(None)
            was_live[0] = on
            if on:
                try:
                    live.set_host(live_reader.sample())
                except (OSError, ValueError, ctypes.ArgumentError):
                    pass

    while not pause(HOST_INTERVAL_S if n else 1):
        n += 1
        try:
            s = reader.sample()
            if s is None:
                if not unreadable:
                    log("host: Windows didn't return its counters - will keep trying")
                    unreadable = True
                continue
            unreadable = False
            if s["cpu_pct"] is None:
                continue  # the first sample only primes the CPU counters
            # programs with the first stored sample, then every 5th
            procs = reader.processes() if written % HOST_PROCS_EVERY == 0 else None
            # the kernel pool by driver with the first stored sample, then hourly (#127)
            tags = reader.pool_tags() if written % HOST_POOL_EVERY == 0 else None
        except (OSError, ValueError, ctypes.ArgumentError) as e:
            log(f"host: {e} - will retry")
            continue
        now = time.time()

        def write():
            conn.execute("INSERT INTO host_stats VALUES (?,?,?,?,?,?,?,?,?,?)",
                         (now, s["cpu_pct"], s["mem_avail"], s["mem_total"], s["commit"], s["commit_limit"],
                          s["pool_paged"], s["pool_nonpaged"], s["handles"], s["uptime_s"]))
            if procs:
                conn.executemany("INSERT INTO host_procs VALUES (?,?,?,?,?,?)",
                                 [(now, name[:80], b, c, h, mx) for name, b, c, h, mx in procs])
                # leak detection runs here, every 5 minutes, rather than on every page view
                history = {}
                for ts, name, private in conn.execute(
                        "SELECT ts, name, private FROM host_procs WHERE ts >= ? ORDER BY ts", (now - 7 * 86400,)):
                    history.setdefault(name, []).append((ts, private))
                store.set_state(conn, host.LEAKS_STATE_KEY, host.leaks(history))
            if tags:
                record_pool_tags(conn, now, tags, s["pool_nonpaged"])
        if _fail_safe("host", conn, write):
            written += 1  # a failed write doesn't push the next program snapshot back


# --------------------------------------------------------------------------- this machine's traffic
def _physical_nic():
    want = CFG.get("traffic_interface")
    if want:
        return want
    try:
        out = subprocess.run(["typeperf", "-qx", "Network Interface"], capture_output=True,
                             text=True, timeout=20).stdout
    except Exception:
        return None
    for m in re.finditer(r"\\Network Interface\((.+?)\)\\Bytes Received/sec", out):
        name = m.group(1)
        if not re.search(r"wi-?fi|wireless|bluetooth|virtual|hyper-v|loopback|isatap|teredo", name, re.I):
            return name
    return None


def traffic_loop(stop):
    """Reads the PHYSICAL port's counters, so Hyper-V VM traffic is included and host<->VM
    internal traffic is not. It also includes LAN traffic (e.g. file copies)."""
    import csv
    nic = _physical_nic()
    if not nic:
        log("traffic: no physical network interface counter found - traffic logging off")
        stop.wait()  # idle rather than return, so the supervisor doesn't keep restarting it
        return
    cmd = ["typeperf", f"\\Network Interface({nic})\\Bytes Received/sec",
           f"\\Network Interface({nic})\\Bytes Sent/sec", "-si", "2",
           "-sc", "1800"]  # 1 h per run, so an orphan can't outlive a killed process for long
    conn = store.db()
    rows = []
    while not stop.is_set():
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        for line in proc.stdout:
            if stop.is_set():
                break
            try:
                vals = next(csv.reader([line]))
                rx, tx = float(vals[1]), float(vals[2])
            except (StopIteration, IndexError, ValueError):
                continue  # header / blank lines
            rows.append((time.time(), round(rx * 8 / 1e6, 2), round(tx * 8 / 1e6, 2)))
            if len(rows) >= 10:
                batch, rows = rows, []
                _fail_safe("traffic", conn, lambda: conn.executemany("INSERT INTO traffic VALUES (?,?,?)", batch))
        proc.kill()
        stop.wait(1)  # run finished (or typeperf died) - start another


# --------------------------------------------------------------------------- the DNS check (step 4.3a)
DNS_INTERVAL_S = 60
DNS_LAN_EVERY_S = 3600       # the LAN's address range is looked up this often (it can take a moment)


def record_dns(conn, ts, results, refused):
    """Store one minute's answers and report the source: working while any resolver answered."""
    conn.executemany("INSERT OR REPLACE INTO dns_1m (ts, resolver, ms, rcode) VALUES (?,?,?,?)",
                     [(ts, r, ms, rcode) for r, ms, rcode in results])
    detail = {"resolvers": [r for r, _, _ in results], "refused": refused}
    if not results:
        sources.report_error(conn, sources.DNS, "no resolver Hearth may ask (see dns_resolvers in config.json)",
                             detail=detail)
    elif all(rcode is None for _, _, rcode in results):
        sources.report_error(conn, sources.DNS, dns_health.NO_ANSWER, detail=detail)
    else:
        sources.report_ok(conn, sources.DNS, detail)


def dns_loop(stop):
    """Once a minute, ask each allowed resolver for dns_probe_name (dns.py) and store the time it
    took, or that it didn't answer."""
    conn = store.db()
    try:
        lan, lan_at = None, 0.0
        while not stop.is_set():
            start = time.time()
            try:
                # read each time: the page can change them (settings.py)
                name = settings.value("dns_probe_name")
                if not dns.valid_name(name):
                    _fail_safe("dns", conn, lambda: sources.report_error(
                        conn, sources.DNS, "dns_probe_name isn't a hostname Hearth will ask for"))
                    stop.wait(DNS_INTERVAL_S)
                    continue
                if start - lan_at >= DNS_LAN_EVERY_S:
                    try:
                        lan = network_settings()[1]
                    except (ValueError, OSError) as e:   # a malformed discovery_subnet: public resolvers still work
                        log(f"dns: couldn't read the LAN's address range ({e})")
                        lan = None
                    lan_at = start
                todo, refused = dns.resolvers(settings.value("dns_resolvers"), analysis._gateway_ip(conn), lan)
                results = []
                for r in todo:
                    try:
                        results.append((r, *dns.probe(r, name)))
                    except (OSError, ValueError):   # no route, no network: that resolver didn't answer
                        results.append((r, None, None))
                ts = int(start // 60 * 60)
                _fail_safe("dns", conn, lambda: record_dns(conn, ts, results, refused))
            except Exception as e:  # noqa: BLE001 - a locked database, a surprise: never end the check
                log(f"dns: {type(e).__name__}: {e}")
            stop.wait(max(1.0, DNS_INTERVAL_S - (time.time() - start)))
    finally:
        conn.close()


# --------------------------------------------------------------------------- alerts (step 4.4a)
ALERT_INTERVAL_S = 30
ALERT_WARMUP_S = 90          # first check after this: sources and readings have settled after a start


def alerts_loop(stop):
    """Check the alert conditions every ALERT_INTERVAL_S (alerts.py)."""
    if stop.wait(ALERT_WARMUP_S):
        return
    conn = store.db()
    try:
        while not stop.is_set():
            start = time.time()
            try:
                _fail_safe("alerts", conn, lambda: alerts.run(conn, start))
                notify.WAKE.set()   # anything raised or cleared goes out now, not at its next look
            except Exception as e:  # noqa: BLE001 - a surprise in one check: try again next time
                log(f"alerts: {type(e).__name__}: {e}")
            stop.wait(max(1.0, ALERT_INTERVAL_S - (time.time() - start)))
    finally:
        conn.close()


# --------------------------------------------------------------------------- notifications (step 6.1)
NOTIFY_IDLE_S = 60           # looked at this often even without a wake-up (retries, the hourly limit)


def notify_loop(stop):
    """Send what's waiting to the notification channels (notify.py): woken by the alerts loop
    after each check, else every NOTIFY_IDLE_S. Its own thread: a slow or hanging channel
    (TIMEOUT_S each) never delays the checks."""
    if stop.wait(ALERT_WARMUP_S):
        return
    conn = store.db()
    try:
        while not stop.is_set():
            try:
                _fail_safe("notify", conn, lambda: notify.run(conn))
            except Exception as e:  # noqa: BLE001 - a surprise in one round: try again next time
                log(f"notify: {type(e).__name__}")
            notify.WAKE.wait(NOTIFY_IDLE_S)
            notify.WAKE.clear()
    finally:
        conn.close()


# --------------------------------------------------------------------------- speed test schedule (step 4.6)
SCHEDULE_RE = re.compile(r"daily ([01]\d|2[0-3]):([0-5]\d)")


def speedtest_due(schedule, now, last_day):
    """Whether a scheduled test should start now: schedule is "daily HH:MM" (anything else, e.g.
    "off", never), it's that minute or up to 10 minutes after, and none ran from it today."""
    m = SCHEDULE_RE.fullmatch(schedule or "")
    if not m:
        return False
    t = time.localtime(now)
    today = time.strftime("%Y-%m-%d", t)
    minutes = t.tm_hour * 60 + t.tm_min - (int(m.group(1)) * 60 + int(m.group(2)))
    return 0 <= minutes < 10 and last_day != today


def speedtest_loop(stop):
    """Start a speed test at the time set in config.json (speedtest_schedule), once a day. Off
    by default; the page can't set it (a schedule makes Hearth fill the line on its own)."""
    schedule = CFG.get("speedtest_schedule", "off")
    if schedule == "off" or not SCHEDULE_RE.fullmatch(str(schedule)):
        if schedule != "off":
            log(f"speedtest_schedule {schedule!r} isn't \"off\" or \"daily HH:MM\" - no scheduled tests")
        stop.wait()
        return
    last_day = None
    while not stop.is_set():
        now = time.time()
        if speedtest_due(schedule, now, last_day):
            last_day = time.strftime("%Y-%m-%d", time.localtime(now))
            try:
                speedtest.start(store.db)
            except speedtest.Busy as e:
                log(f"scheduled speed test skipped: {e}")
        stop.wait(30)


# --------------------------------------------------------------------------- weekly digest (step 4.7)
BACKUP_CHECK_S = 600


def backup_loop(stop):
    """A daily backup of hearth.db at backup_time (backup.py), or at once if the last is over
    36 h old; checked every ten minutes. Its state is a data source, so a failing one is seen."""
    if backup.keep() == 0:
        _report_unconfigured(sources.BACKUP, "turned off in config.json (backup_keep: 0)")
        stop.wait()
        return
    if stop.wait(300):                 # not in the busy first minutes after a start
        return
    conn = store.db()
    failed_at = None
    try:
        while not stop.is_set():
            try:
                failed_at = _backup_round(conn, time.time(), failed_at)
            except Exception as e:  # noqa: BLE001 - a surprise (a file gone mid-look): try again next round (#130 review)
                log(f"backup: {type(e).__name__}: {e}")
            stop.wait(BACKUP_CHECK_S)
    finally:
        conn.close()


BACKUP_RETRY_S = 3600   # after a failed backup (a full disk, say), the next try waits this long


def _backup_round(conn, now, failed_at):
    """One look: make a backup if one's due (not within BACKUP_RETRY_S of a failure), and keep
    the source's state. Returns when the last attempt failed, or None."""
    have = backup.existing(backup.folder())
    try:
        last = os.path.getmtime(have[-1][1]) if have else None
    except OSError:          # removed since the folder was listed
        last = None
    if not backup.due(now, last, backup.at()):
        if (sources.read(conn, sources.BACKUP) or {}).get("ok") is None and have and last:
            # the first look after a start, nothing due: say what's there
            sources.report_ok(conn, sources.BACKUP, {"file": os.path.basename(have[-1][1]), "kept": len(have)}, last)
            conn.commit()
        return failed_at
    if failed_at is not None and now - failed_at < BACKUP_RETRY_S:
        return failed_at     # not every ten minutes while it can't work: 168 MB copied each time
    try:
        res = backup.make(now=now)
    except backup.BackupError as e:
        sources.report_error(conn, sources.BACKUP, str(e), now)
        conn.commit()
        log(f"backup: {e}")
        return now
    sources.report_ok(conn, sources.BACKUP, {"file": res["file"], "bytes": res["bytes"], "kept": res["kept"]}, now)
    conn.commit()
    log(f"backup: {res['file']} ({res['bytes'] / 1e6:.0f} MB, {res['took_s']} s)")
    return None


DIGEST_CHECK_S = 600


def digest_loop(stop):
    """Build last week's digest when it's due (digest.due): Monday from 08:00, or at start when
    it's missing. Checked every ten minutes."""
    if stop.wait(120):                 # let the first readings and the episode store settle
        return
    conn = store.db()
    try:
        while not stop.is_set():
            try:
                week = digest.due(conn, time.time())
                if week is not None:
                    _fail_safe("digest", conn, lambda: digest.store_week(conn, week))
            except Exception as e:  # noqa: BLE001 - try again at the next check
                log(f"digest: {type(e).__name__}: {e}")
            stop.wait(DIGEST_CHECK_S)
    finally:
        conn.close()
