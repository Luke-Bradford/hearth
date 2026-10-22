"""SQLite storage. One connection per thread (sqlite3 connections aren't shared)."""
import json
import sqlite3
import time

from .config import CFG, DB_PATH, log

SCHEMA = """
CREATE TABLE IF NOT EXISTS pings (ts REAL NOT NULL, target TEXT NOT NULL, rtt REAL);
CREATE INDEX IF NOT EXISTS ix_pings ON pings(target, ts);
CREATE INDEX IF NOT EXISTS ix_pings_ts ON pings(ts);
CREATE TABLE IF NOT EXISTS pings_1m (ts INTEGER NOT NULL, target TEXT NOT NULL, n INTEGER NOT NULL,
    lost INTEGER NOT NULL, avg REAL, max REAL, jitter REAL, PRIMARY KEY (target, ts));
CREATE INDEX IF NOT EXISTS ix_pings_1m_ts ON pings_1m(ts);
CREATE TABLE IF NOT EXISTS spike_hours (hour INTEGER PRIMARY KEY, spikes INTEGER NOT NULL, bad INTEGER NOT NULL);
-- slowdowns and outages, stored once final (raw pings, which they're built from, last 48 h).
-- Episodes never overlap; a truncated one began before the raw data it was built from
CREATE TABLE IF NOT EXISTS episodes (start INTEGER PRIMARY KEY, end INTEGER NOT NULL, kind TEXT NOT NULL,
    level TEXT NOT NULL, truncated INTEGER NOT NULL DEFAULT 0, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_episodes_end ON episodes(end);
-- where each device was: a row only when its place changes (held for two mesh readings).
-- node: the mesh unit's MAC, or NULL for "location unknown"; how: 'mesh' | 'timing' | 'unknown'
CREATE TABLE IF NOT EXISTS device_places (ts REAL NOT NULL, device TEXT NOT NULL, node TEXT,
    how TEXT NOT NULL, PRIMARY KEY (device, ts));
CREATE TABLE IF NOT EXISTS devices (ip TEXT PRIMARY KEY, mac TEXT, name TEXT,
    first_seen REAL, last_seen REAL, online INTEGER, app_name TEXT, last_answered REAL);
CREATE TABLE IF NOT EXISTS events (ts REAL NOT NULL, kind TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS ix_events ON events(ts);
CREATE TABLE IF NOT EXISTS sweeps (start REAL NOT NULL, end REAL NOT NULL);
CREATE TABLE IF NOT EXISTS wifi (ts REAL NOT NULL, ssid TEXT, bssid TEXT, band TEXT, channel INTEGER,
    signal INTEGER, util INTEGER, stations INTEGER);
CREATE INDEX IF NOT EXISTS ix_wifi ON wifi(ts);
CREATE TABLE IF NOT EXISTS traffic (ts REAL NOT NULL, rx_mbps REAL, tx_mbps REAL);
CREATE INDEX IF NOT EXISTS ix_traffic ON traffic(ts);
CREATE TABLE IF NOT EXISTS groups (id INTEGER PRIMARY KEY, members TEXT NOT NULL, created REAL, updated REAL);
CREATE TABLE IF NOT EXISTS topology (ts REAL NOT NULL, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_topology ON topology(ts);
CREATE TABLE IF NOT EXISTS labels (key TEXT PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT);
-- internet traffic per device, from the router: bytes moved during the `dur` seconds ending at ts
CREATE TABLE IF NOT EXISTS usage (ts REAL NOT NULL, mac TEXT NOT NULL, dur REAL NOT NULL,
    rx INTEGER NOT NULL, tx INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS ix_usage ON usage(ts);
CREATE TABLE IF NOT EXISTS usage_1h (ts INTEGER NOT NULL, mac TEXT NOT NULL, rx INTEGER NOT NULL,
    tx INTEGER NOT NULL, PRIMARY KEY (mac, ts));
CREATE INDEX IF NOT EXISTS ix_usage_1h_ts ON usage_1h(ts);
-- each mesh node's uplink at every mesh reading: how its link to the rest of the mesh held up
CREATE TABLE IF NOT EXISTS mesh_links (ts REAL NOT NULL, mac TEXT NOT NULL, name TEXT, backhaul TEXT,
    signal TEXT, online INTEGER);
CREATE INDEX IF NOT EXISTS ix_mesh_links ON mesh_links(ts);
-- each satellite's backhaul at every mesh reading: signal (dBm) and link rates (Mb/s) per band
CREATE TABLE IF NOT EXISTS mesh_backhaul (ts REAL NOT NULL, mac TEXT NOT NULL, band TEXT NOT NULL,
    rssi INTEGER, rate_rx INTEGER, rate_tx INTEGER);
CREATE INDEX IF NOT EXISTS ix_mesh_backhaul ON mesh_backhaul(ts);
-- the computer running Hearth: a sample a minute, and its biggest programs every 5 minutes
CREATE TABLE IF NOT EXISTS host_stats (ts REAL NOT NULL, cpu REAL, mem_avail INTEGER, mem_total INTEGER,
    commit_bytes INTEGER, commit_limit INTEGER, pool_paged INTEGER, pool_nonpaged INTEGER, handles INTEGER,
    uptime_s INTEGER);
CREATE INDEX IF NOT EXISTS ix_host_stats ON host_stats(ts);
CREATE TABLE IF NOT EXISTS host_procs (ts REAL NOT NULL, name TEXT NOT NULL, private INTEGER,
    count INTEGER, handles INTEGER, max_handles INTEGER);
CREATE INDEX IF NOT EXISTS ix_host_procs ON host_procs(ts);
CREATE TABLE IF NOT EXISTS router_clients (mac TEXT PRIMARY KEY, ip TEXT, name TEXT, online INTEGER,
    last_seen REAL);
-- the router's own health, about once a minute: CPU temperature, uptime, load, memory in use
CREATE TABLE IF NOT EXISTS router_stats (ts REAL NOT NULL, temp_c REAL, uptime_s INTEGER, load1 REAL,
    mem_used_pct REAL);
CREATE INDEX IF NOT EXISTS ix_router_stats ON router_stats(ts);
-- hourly summaries of the detail tables above, kept as long as per-minute pings: month-scale
-- trends (router temperature, backhaul signal, this computer's traffic and health)
CREATE TABLE IF NOT EXISTS router_stats_1h (ts INTEGER PRIMARY KEY, temp_avg REAL, temp_max REAL,
    load_avg REAL, mem_avg REAL, restarted INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS mesh_backhaul_1h (ts INTEGER NOT NULL, mac TEXT NOT NULL, band TEXT NOT NULL,
    rssi_avg REAL, rssi_min INTEGER, rx_avg REAL, tx_avg REAL, n INTEGER NOT NULL, PRIMARY KEY (ts, mac, band));
CREATE TABLE IF NOT EXISTS traffic_1h (ts INTEGER PRIMARY KEY, rx_avg REAL, tx_avg REAL, rx_max REAL,
    tx_max REAL);
-- whole-home internet traffic as the router's UPnP reports it: bytes in the `dur` seconds to ts
CREATE TABLE IF NOT EXISTS traffic_wan (ts REAL NOT NULL, rx INTEGER NOT NULL, tx INTEGER NOT NULL,
    dur REAL NOT NULL);
CREATE INDEX IF NOT EXISTS ix_traffic_wan ON traffic_wan(ts);
CREATE TABLE IF NOT EXISTS traffic_wan_1h (ts INTEGER PRIMARY KEY, rx INTEGER, tx INTEGER);
-- speed tests (speedtest.py): Mb/s each way, the round trip idle and while full, its grade;
-- a failed one keeps its error (and no figures)
CREATE TABLE IF NOT EXISTS speedtests (ts REAL PRIMARY KEY, ended REAL NOT NULL, down REAL, up REAL, idle_ms REAL,
    loaded_down_ms REAL, loaded_up_ms REAL, grade TEXT, server TEXT, error TEXT);
-- weekly digests (digest.py): one per week, by its Monday midnight; kept a year
CREATE TABLE IF NOT EXISTS digests (week_start INTEGER PRIMARY KEY, data TEXT NOT NULL);
-- the DNS check (dns.py): one row per resolver a minute; ms NULL when it didn't answer in time,
-- rcode the answer's code (0 answered, 3 no such name, 5 refused...), NULL with no answer
CREATE TABLE IF NOT EXISTS dns_1m (ts INTEGER NOT NULL, resolver TEXT NOT NULL, ms REAL, rcode INTEGER,
    PRIMARY KEY (resolver, ts));
CREATE INDEX IF NOT EXISTS ix_dns_1m_ts ON dns_1m(ts);
-- alerts (alerts.py): a state alert lasts while its condition holds (cleared NULL); an event
-- alert happened once (cleared = first). seen: you've looked; missing: checks gone in a row
CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL, level TEXT NOT NULL,
    text TEXT NOT NULL, tab TEXT, item TEXT, first REAL NOT NULL, last REAL NOT NULL, cleared REAL,
    seen INTEGER NOT NULL DEFAULT 0, missing INTEGER NOT NULL DEFAULT 0, kind TEXT NOT NULL DEFAULT 'state');
CREATE INDEX IF NOT EXISTS ix_alerts_key ON alerts(key);
CREATE UNIQUE INDEX IF NOT EXISTS ux_alerts_open ON alerts(key) WHERE cleared IS NULL AND kind = 'state';
-- every MAC ever seen (alerts.py, new devices): by MAC, so a new DHCP address isn't a new device;
-- private: the address is locally administered (a phone's or laptop's rotating private address)
CREATE TABLE IF NOT EXISTS device_macs (mac TEXT PRIMARY KEY, first_seen REAL NOT NULL, private INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS ix_alerts_cleared ON alerts(cleared);
CREATE TABLE IF NOT EXISTS host_stats_1h (ts INTEGER PRIMARY KEY, cpu_avg REAL, mem_avail_min INTEGER,
    mem_total_max INTEGER, commit_max INTEGER, commit_limit_max INTEGER, pool_paged_max INTEGER,
    pool_nonpaged_max INTEGER, handles_max INTEGER, uptime_min INTEGER);
"""

RAW_HOURS = float(CFG["raw_retention_hours"])
ROLLUP_DAYS = float(CFG["rollup_retention_days"])
DETAIL_DAYS = float(CFG["detail_retention_days"])


def db():
    c = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=NORMAL")
    return c


def init_db():
    c = db()
    c.executescript(SCHEMA)
    # columns added after a table first shipped
    for table, col, kind in (("devices", "vendor", "TEXT"), ("devices", "friendly", "TEXT"),
                             ("devices", "model", "TEXT"), ("host_stats", "uptime_s", "INTEGER"),
                             ("host_procs", "max_handles", "INTEGER"), ("devices", "app_name", "TEXT"),
                             ("devices", "last_answered", "REAL"), ("pings_1m", "jitter", "REAL")):
        if col not in {r[1] for r in c.execute(f"PRAGMA table_info({table})")}:
            if col == "app_name":
                # friendly used to hold UPnP (app) names too, which can't be told apart now:
                # clear it so the next sweep refills it with mDNS names only. Done first: the
                # UPDATE opens a transaction the ALTER then joins, so a crash before the commit
                # undoes both and the clear runs again on the next start
                c.execute("UPDATE devices SET friendly=NULL")
            c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {kind}")
    c.commit()
    c.close()


def move_device_history(conn, old_id, new_id):
    """A device's id changed (its MAC became shared with other IPs, or stopped being): carry
    its ping history and your name for it over to the new id, so the device keeps one history.
    Nothing is deleted: a per-minute row for a minute the new id already has, or your name if
    the new id already has one, stays under the old id (where retention prunes old minutes)."""
    if old_id == new_id:
        return
    conn.execute("UPDATE pings SET target=? WHERE target=?", (new_id, old_id))
    conn.execute("UPDATE OR IGNORE pings_1m SET target=? WHERE target=?", (new_id, old_id))
    conn.execute("UPDATE OR IGNORE labels SET key=? WHERE key=?", (new_id, old_id))


def id_in_use(conn, tid):
    """Does anything (pings, per-minute history, your name) sit under this device id?"""
    return any(conn.execute(q, (tid,)).fetchone() for q in (
        "SELECT 1 FROM pings WHERE target=? LIMIT 1",
        "SELECT 1 FROM pings_1m WHERE target=? LIMIT 1",
        "SELECT 1 FROM labels WHERE key=? LIMIT 1"))


def add_event(conn, kind, detail, ts=None):
    conn.execute("INSERT INTO events VALUES (?,?,?)", (ts or time.time(), kind, detail))


def get_state(conn, key, default=None, strict=False):
    """A saved state value, or default if it's missing. An unreadable row also gives default
    (a damaged row would otherwise fail every loop that reads it, every run, until someone
    edited the database) and is logged once - unless strict: then it raises ValueError, for
    state where starting over would be unsafe (the mesh's pinned certificates)."""
    row = conn.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
    if not row:
        return default
    try:
        value = json.loads(row[0])
    except (TypeError, ValueError) as e:
        if strict:
            raise ValueError(f"saved state {key!r} is unreadable") from e
        _report_damaged(key, "unreadable")
        return default
    # a default also says what kind of value is expected: a saved value of another kind (a
    # list where a dict belongs) is treated like an unreadable one. A saved null is "nothing".
    if default is not None and value is not None and not _same_kind(value, default):
        if strict:
            raise ValueError(f"saved state {key!r} has the wrong shape")
        _report_damaged(key, "the wrong shape")
        return default
    return value


def _same_kind(value, default):
    number = (int, float)
    if isinstance(default, number) and not isinstance(default, bool):
        return isinstance(value, number) and not isinstance(value, bool)
    return isinstance(value, type(default))


def _report_damaged(key, what):
    if key not in _damaged_logged:
        _damaged_logged.add(key)
        log(f"state: saved {key!r} is {what} - starting it afresh")


_damaged_logged = set()  # state keys already reported as unreadable (once per process)


def set_state(conn, key, value):
    conn.execute("INSERT OR REPLACE INTO state VALUES (?,?)", (key, json.dumps(value)))


def labels(conn):
    return dict(conn.execute("SELECT key, name FROM labels"))


def set_label(conn, key, name):
    if name:
        conn.execute("INSERT OR REPLACE INTO labels VALUES (?,?)", (key, name))
    else:
        conn.execute("DELETE FROM labels WHERE key=?", (key,))


def topology_history(conn, since):
    """Snapshots in force during [since, now]: the last one before `since` plus all after."""
    first = conn.execute("SELECT ts, data FROM topology WHERE ts <= ? ORDER BY ts DESC LIMIT 1", (since,)).fetchall()
    rest = conn.execute("SELECT ts, data FROM topology WHERE ts > ? ORDER BY ts", (since,)).fetchall()
    return [(ts, {**json.loads(d), "_ts": ts}) for ts, d in first + rest]  # _ts: stable cache key


def topology_at(history, ts):
    cur = None
    for t, data in history:
        if t > ts:
            break
        cur = data
    return cur if cur is not None else (history[0][1] if history else None)


def add_usage(conn, now, dur, deltas):
    """Record one router reading: {mac: (rx bytes, tx bytes)} moved in the last `dur` seconds.
    The hourly table is added to directly, so long-range views need no rollup job. A reading
    is booked to the hour it was taken in, even when `dur` reaches into earlier hours (after
    a gap of up to ROUTER_MAX_GAP_S): the totals are right, the hour boundaries approximate."""
    hour = int(now // 3600 * 3600)
    for mac, (rx, tx) in deltas.items():
        conn.execute("INSERT INTO usage VALUES (?,?,?,?,?)", (now, mac, dur, rx, tx))
        conn.execute("""INSERT INTO usage_1h VALUES (?,?,?,?)
                        ON CONFLICT (mac, ts) DO UPDATE SET rx = rx + excluded.rx, tx = tx + excluded.tx""",
                     (hour, mac, rx, tx))


def save_router_clients(conn, now, clients):
    for c in clients:
        conn.execute("INSERT OR REPLACE INTO router_clients VALUES (?,?,?,?,?)",
                     (c["mac"], c["ip"], c["name"], int(c["online"]), now))


def add_router_stats(conn, now, st):
    conn.execute("INSERT INTO router_stats VALUES (?,?,?,?,?)",
                 (now, st["temp_c"], st["uptime_s"], st["load1"], st["mem_used_pct"]))


def rollup(conn, upto):
    """Fold whole minutes of raw pings (up to `upto`, exclusive) into pings_1m."""
    row = conn.execute("SELECT MAX(ts) FROM pings_1m").fetchone()
    start = row[0] + 60 if row[0] is not None else conn.execute("SELECT MIN(ts) FROM pings").fetchone()[0]
    if start is None:
        return
    start, upto = int(start // 60 * 60), int(upto // 60 * 60)
    if upto <= start:
        return
    # jitter: the mean difference between one reply's round trip and the next within the minute
    # (RFC 3550's measure, without its smoothing); a lost ping leaves no difference either side.
    # LAG() is a window function: SQLite 3.25 or later (Python 3.8+ ships newer)
    conn.execute(
        """INSERT OR REPLACE INTO pings_1m (ts, target, n, lost, avg, max, jitter)
           SELECT m, target, COUNT(*), SUM(CASE WHEN rtt IS NULL THEN 1 ELSE 0 END), AVG(rtt), MAX(rtt),
                  AVG(ABS(diff))
           FROM (SELECT CAST(ts / 60 AS INTEGER) * 60 AS m, target, rtt,
                        rtt - LAG(rtt) OVER (PARTITION BY target, CAST(ts / 60 AS INTEGER) ORDER BY ts) AS diff
                 FROM pings WHERE ts >= ? AND ts < ?)
           GROUP BY m, target""", (start, upto))


# (hourly table, detail table, the hourly row's columns as aggregates of the detail rows, extra
# grouping columns). "h" is the hour a row falls in.
_H = "CAST(ts / 3600 AS INTEGER) * 3600"
HOURLY = (
    ("router_stats_1h", "router_stats",
     # restarted: the router booted (reading time minus its uptime) within the hour
     f"AVG(temp_c), MAX(temp_c), AVG(load1), AVG(mem_used_pct), "
     f"MAX(CASE WHEN uptime_s IS NOT NULL AND ts - uptime_s >= {_H} THEN 1 ELSE 0 END)", ()),
    ("mesh_backhaul_1h", "mesh_backhaul", "AVG(rssi), MIN(rssi), AVG(rate_rx), AVG(rate_tx), COUNT(*)",
     ("mac", "band")),
    ("traffic_1h", "traffic", "AVG(rx_mbps), AVG(tx_mbps), MAX(rx_mbps), MAX(tx_mbps)", ()),
    ("traffic_wan_1h", "traffic_wan", "SUM(rx), SUM(tx)", ()),
    ("host_stats_1h", "host_stats", "AVG(cpu), MIN(mem_avail), MAX(mem_total), MAX(commit_bytes), "
     "MAX(commit_limit), MAX(pool_paged), MAX(pool_nonpaged), MAX(handles), MIN(uptime_s)", ()),
)


HOUR_START_SLACK_S = 120   # the first detail row this close to an hour's start: that hour counts as whole
HOUR_CLOSE_DELAY_S = 120   # an hour is rolled up this long after it ends (late detail rows still land in it)


def rollup_hourly(conn, now):
    """Fold whole past hours of the detail tables into their hourly tables. Each resumes from the
    hour after its newest row - so hours missed while Hearth was stopped are filled from the
    detail rows still kept (detail_retention_days) - and the first time from the first whole
    hour of detail data (a partial first hour isn't written as if it were whole). Upserts: a
    re-run changes nothing. An hour is closed a couple of minutes after it ends."""
    upto = int((now - HOUR_CLOSE_DELAY_S) // 3600 * 3600)
    for dst, src, aggs, extra in HOURLY:
        newest = conn.execute(f"SELECT MAX(ts) FROM {dst}").fetchone()[0]
        if newest is not None:
            start = int(newest) + 3600
        else:
            first = conn.execute(f"SELECT MIN(ts) FROM {src}").fetchone()[0]
            if first is None:
                continue
            # data from (nearly) the hour's start makes it whole; from later in it, partial
            hour = int(first // 3600 * 3600)
            start = hour if first - hour <= HOUR_START_SLACK_S else hour + 3600
        if start >= upto:
            continue
        cols = "".join(f", {c}" for c in extra)
        conn.execute(f"INSERT OR REPLACE INTO {dst} SELECT {_H}{cols}, {aggs} FROM {src} "
                     f"WHERE ts >= ? AND ts < ? GROUP BY 1{cols}", (start, upto))


def prune(conn, now):
    # never drop raw rows that haven't been rolled up yet
    rolled = conn.execute("SELECT MAX(ts) FROM pings_1m").fetchone()[0] or 0
    conn.execute("DELETE FROM pings WHERE ts < ?", (min(now - RAW_HOURS * 3600, rolled),))
    conn.execute("DELETE FROM pings_1m WHERE ts < ?", (now - ROLLUP_DAYS * 86400,))
    conn.execute("DELETE FROM events WHERE ts < ?", (now - 86400 * float(CFG["retention_days"]),))
    conn.execute("DELETE FROM dns_1m WHERE ts < ?", (now - 86400 * float(CFG["retention_days"]),))
    # layouts long gone, and the names users gave them (ids are never reused)
    conn.execute("DELETE FROM labels WHERE key IN (SELECT 'grp:' || id FROM groups WHERE updated < ?)",
                 (now - 30 * 86400,))
    conn.execute("DELETE FROM groups WHERE updated < ?", (now - 30 * 86400,))
    # devices not seen for a month (old DHCP leases, phones' rotating private MACs)
    conn.execute("DELETE FROM devices WHERE last_seen < ?", (now - 30 * 86400,))
    conn.execute("DELETE FROM usage_1h WHERE ts < ?", (now - ROLLUP_DAYS * 86400,))
    # kept as long as per-minute data: momentary spike counts for long ranges ("usual" reads only
    # its own window); episodes likewise
    conn.execute("DELETE FROM spike_hours WHERE hour < ?", (now - ROLLUP_DAYS * 86400,))
    conn.execute("DELETE FROM episodes WHERE end < ?", (now - ROLLUP_DAYS * 86400,))
    # places: older rows go, except each device's newest one at or before the cutoff - the place
    # in force at the start of the longest range
    cutoff = now - ROLLUP_DAYS * 86400
    conn.execute("""DELETE FROM device_places WHERE ts < ? AND ts < (SELECT MAX(p.ts) FROM device_places p
                    WHERE p.device = device_places.device AND p.ts <= ?)""", (cutoff, cutoff))
    # ...and that last row too once nothing newer exists and the device has left Hearth's lists -
    # its devices and the router's clients (each drops what it hasn't seen for a month): no range
    # can reach a place that old any more
    conn.execute("""DELETE FROM device_places WHERE ts < ?
                    AND NOT EXISTS (SELECT 1 FROM device_places p WHERE p.device = device_places.device AND p.ts >= ?)
                    AND NOT EXISTS (SELECT 1 FROM devices d WHERE 'dev:' || lower(d.mac) = device_places.device
                                    OR 'dev:ip:' || d.ip = device_places.device)
                    AND NOT EXISTS (SELECT 1 FROM router_clients r
                                    WHERE 'dev:' || lower(r.mac) = device_places.device)""", (cutoff, cutoff))
    conn.execute("DELETE FROM router_clients WHERE last_seen < ?", (now - 30 * 86400,))
    conn.execute("DELETE FROM mesh_links WHERE ts < ?", (now - ROLLUP_DAYS * 86400,))
    for dst, *_ in HOURLY:
        conn.execute(f"DELETE FROM {dst} WHERE ts < ?", (now - ROLLUP_DAYS * 86400,))
    for table in ("wifi", "traffic", "topology", "sweeps", "usage", "host_stats", "host_procs", "mesh_backhaul",
                  "router_stats", "traffic_wan"):
        conn.execute(f"DELETE FROM {table} WHERE {'end' if table == 'sweeps' else 'ts'} < ?",
                     (now - DETAIL_DAYS * 86400,))
