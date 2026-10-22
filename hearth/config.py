"""Settings. Every key is optional: config.json only overrides these defaults.

Nothing here describes a particular home - the layout (router, mesh/extender groups,
which devices share a link) is discovered at runtime.
"""
import json
import os
import platform
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(HERE, "hearth.db")
LEGACY_DB_PATH = os.path.join(HERE, "netmon.db")  # name used before the rename
OUI_PATH = os.path.join(HERE, "oui.csv")
IS_WIN = platform.system() == "Windows"

DEFAULTS = {
    "web_port": 8080,
    "allowed_hosts": [],           # extra host names the dashboard may be reached by (IPs always work)
    "internet_targets": ["1.1.1.1", "8.8.8.8"],
    "gateway": None,               # auto: the default route
    "discovery_subnet": None,      # auto: this machine's LAN, e.g. "192.168.1.0/24"
    "exclude_ips": [],             # devices never to ping
    "core_interval_s": 1.0,        # router, ISP edge, internet targets
    "device_interval_s": 5.0,      # every live device on the LAN
    "sleepy_interval_s": 60.0,     # devices that keep missing replies (phones asleep)
    "ping_timeout_ms": 1000,
    "spike_over_baseline_ms": 40,
    "discovery_interval_s": 300,
    "discovery_workers": 8,
    "topology_interval_s": 120,
    "topology_window_min": 20,
    "path_check_interval_s": 600,
    "wifi_scan_interval_s": 30,
    "router_poll_interval_s": 60,  # read per-device traffic from the router (min 15; "Refresh now" anytime)
    "router_credentials_file": None,  # default: ~/.hearth/router.env; no file = router features off
    "router_temp_warn_c": 75,      # router CPU temperature shown amber from here...
    "router_temp_bad_c": 85,       # ...and red from here (Hearth's choice, not a maker's limit)
    "mesh_poll_interval_s": 300,   # read the mesh layout (Deco) from the same file's DECO_PASSWORD (min 60)
    "mesh_host": None,             # the main Deco's address; auto: a TP-Link device (by MAC maker), then pinned
    "mesh_auto_trust": True,       # accept the main Deco's new certificate by itself if its login keys and MAC are unchanged
    "alert_attention": True,       # alerts (alerts.py): anything in "Needs attention" at fair or poor
    "alert_outages": True,         # ...an outage that ended
    "alert_calls": False,          # ...calls sounding poor for five minutes
    "alert_new_devices": True,     # ...a device joining that Hearth has never seen (by MAC)
    "speedtest_server": "https://speed.cloudflare.com",   # speed tests go here (https only)
    "notify_level": "warn",        # notifications (notify.py): the lowest level sent, "warn" or "bad"
    "dashboard_url": "",           # e.g. "http://192.168.1.60:8080": messages link to the Alerts list there
    "speedtest_schedule": "off",   # "off" or "daily HH:MM": only here - the page can't start them on its own
    "dns_resolvers": ["gateway", "1.1.1.1"],   # asked once a minute: "gateway" is the router; see dns.allowed
    "dns_probe_name": "www.google.com",        # the name they're asked for
    "upnp": True,                  # read the router's UPnP gateway (traffic, link, public IP) if it offers one
    "raw_retention_hours": 48,
    "rollup_retention_days": 400,
    "detail_retention_days": 7,
    "retention_days": 90,          # events
    "usage_month_starts": 1,       # the day (1-28) a usage month begins: when your allowance resets
    "backup_keep": 7,              # daily backups of hearth.db kept (backup.py); 0 turns them off
    "backup_dir": "backups",       # where: relative to this folder, or a full path (another disk is better)
    "backup_time": "03:30",        # when each day (one is made at once if the last is over 36 h old)
}


def _load():
    cfg = dict(DEFAULTS)
    path = os.path.join(HERE, "config.json")
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                user = json.load(f)
        except ValueError as e:  # JSONDecodeError, or text that isn't UTF-8
            raise SystemExit(f"config.json can't be read: {e}. Fix it (it must be JSON, like "
                             f'{{"web_port": 8080}}) or remove it to use the defaults.') from None
        except OSError as e:  # e.g. no permission, or a folder of that name
            raise SystemExit(f"config.json can't be opened ({type(e).__name__}: {e.strerror or e}). "
                             f"Check it's a readable file, or remove it to use the defaults.") from None
        if not isinstance(user, dict):
            raise SystemExit('config.json must hold a JSON object, like {"web_port": 8080}.')
        cfg.update({k: v for k, v in user.items() if not k.startswith("_")})
    return cfg


CFG = _load()

# --- identifiers shared by collectors, analysis and the dashboard (single source of truth)
TARGET_GATEWAY = "gateway"
TARGET_ISP = "isp"
INET_PREFIX = "inet:"
DEV_PREFIX = "dev:"
GROUP_PREFIX = "grp:"

POS_LOCAL = "local"
POS_RELAY = "relay"
POS_GATEWAY = "gateway"
POS_ISP = "isp"
POS_INTERNET = "internet"

EV_PATH = "path"
EV_WIFI_CHANNEL = "wifi_channel"
EV_WIFI_LOST = "wifi_lost"
EV_WIFI_BACK = "wifi_back"
EV_ISP_PATH = "isp_path"
EV_MESH = "mesh"
EV_ROUTER = "router"
MESH_STATE_KEY = "mesh"  # state row: the mesh system's latest reading
GATEWAY_STATE_KEY = "gateway_ip"  # state row: {ip, ts} - the router's address, as discovery last found it
GATEWAY_STALE_SWEEPS = 3          # a saved router address older than this many sweeps isn't used

# device presence. A device stays ping-polled while it answered ping in any of the last
# KEEP_SWEEPS sweeps; one still on the network (in the ARP table) that answered no ping in
# those sweeps, after answering before, is shown as asleep - a sleeping PC's network
# card often keeps answering ARP. Offline needs OFFLINE_AFTER_MISSES sweeps in a row without
# a sign of it, so a single missed sweep doesn't log a gone/back pair (the same idea as Home
# Assistant's consider_home grace period).
KEEP_SWEEPS = 3
OFFLINE_AFTER_MISSES = 2
STATE_ONLINE, STATE_ASLEEP, STATE_OFFLINE = "online", "asleep", "offline"


def inet_target(ip):
    return INET_PREFIX + ip


def device_target(mac, ip):
    """Devices are keyed by MAC so history survives DHCP handing out a new IP."""
    return DEV_PREFIX + (mac if mac else "ip:" + ip)


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)
