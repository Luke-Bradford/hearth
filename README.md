# Hearth

Home network health at a glance. Hearth pings your router, your internet connection and every
device at home, **works out the layout of your network by itself**, and tells you plainly what's
wrong and **which link caused it** — your Wi-Fi, a mesh unit, the router, the broadband line or
the wider internet.

Pure Python standard library: nothing to install but Python, no Administrator rights, no
account, nothing sent anywhere about your home.

## Install

1. Install **Python 3.9 or newer** on a computer that's always on at home (Windows or Linux).
   On Windows, tick "Add Python to PATH" in the installer.
2. Download this folder and put it somewhere permanent (for example `C:\hearth`).
3. Double-click **`start-hearth.bat`** (on Linux: `python3 hearth.py`). Allow it through the
   firewall on **private networks** when Windows asks.
4. Open the dashboard from any device at home: **`http://<that-computer>:8080`** (on the
   computer itself: `http://localhost:8080`).

Give it about five minutes: the first visit shows a short welcome while Hearth learns your
network. Names come from your network (device names, makers); click ✎ to rename anything.

**Start with Windows:** double-click **`install-startup.bat`** once. It puts a shortcut in your
Startup folder, so Hearth starts when you sign in. `install-startup.bat /remove` undoes it.
Hearth then runs while you're signed in: it stops when you sign out, and after a restart it waits
for you to sign in again (time it wasn't running shows as "not measured"). For a computer that
restarts on its own, turn on automatic sign-in, or run `start-hearth.bat` from a Task Scheduler
task set to "Run whether user is logged on or not".

**Linux:** Hearth pings with ICMP "ping sockets", which need no root on most distributions
(`sysctl net.ipv4.ping_group_range` shows `0 2147483647`). If yours doesn't allow them, Hearth
says so and falls back to the `ping` program (works, costs more CPU); to allow them:
`sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"`. Run it at boot with a systemd user
service or cron's `@reboot`.

**Updating:** stop Hearth, replace the folder's files (keep `hearth.db` and `config.json`),
start it again. The open dashboard reloads itself when it notices the new version.

## What you'll see

| Tab | What it answers |
| --- | --- |
| **Overview** | Is everything all right? One sentence, the headline figures (router, internet quality, today's use, the mesh, Wi-Fi, calls), the last 24 hours in 15-minute blocks, what needs attention, and last week in a few lines. |
| **Network** | The map of your network - drawn from your mesh system if Hearth can read it, otherwise worked out from timing - Wi-Fi radios in range and how well each mesh link and wireless device is connected. Click anything for its details. |
| **Devices** | Every device, searchable and filterable: online or not, Wi-Fi or wired, which unit. |
| **History** | Latency and loss over any range (15 minutes to a year), how calls would have sounded and how fast DNS answered, every slowdown and outage, the **outage log**, and the month's **ISP report card**. |
| **Usage** | Who uses the internet (with a supported router), this month's usage from the day your allowance resets, and a **speed test**. |
| **System** | **Security** (what can reach your home from the internet - port forwards, DMZ, remote access - and the router's and mesh's firmware), **Setup** (what Hearth found and what you could add), the computer running Hearth (naming the driver behind a kernel memory leak), the DNS check, the data sources and **Settings**. |

Every link in the page can be bookmarked or shared (the address says the tab, the time range and
what's open). There's a light and a dark theme, and it works on a phone.

### Slowdowns and outages

Every second Hearth pings the router and two internet addresses (1.1.1.1 and 8.8.8.8); every few
seconds, every device. A reply far slower than usual, or none, is a *spike*; spikes close
together are judged together as an **episode**:

| Episode | When |
| --- | --- |
| Home network outage | No replies from the internet for 10 s or more, and the router silent too |
| Outage | No replies from the internet for 10 s or more, while the router answers |
| Problem | Replies lost in 3 or more seconds, or 2 minutes or more of slow replies |
| Slow spell | 30 s or more of slow replies, or 3 or more bursts close together |

Anything shorter is a *momentary spike*: counted and compared with what's usual for your
connection, but not listed unless you ask. Loss needs both internet addresses silent, so one
rate-limiting pings can't fake an outage. Time Hearth wasn't running is "not measured", never an
outage. Each episode says which link was at fault, who was using the internet then, and whether
DNS or a speed test was involved.

### Alerts

The **Alerts** button (top right) lists what needs you: anything in "Needs attention", outages
once they end, a device Hearth has never seen joining, and (if you turn it on) calls sounding
poor. Each is said once, kept up to date while it lasts, and cleared once it's gone. Choose the
kinds in **System, Settings**. To be told on your phone, set up **notifications** (below).

### Notifications

Hearth can send each alert to your phone or chat as it's raised: to **ntfy** (free, no account:
install the ntfy app, subscribe to a topic name only you know, e.g. `hearth-7f3k9q2x`), to a
**Discord** or **Slack** webhook, or to any other webhook (as JSON). Open the dashboard **on the
computer running Hearth**, go to **System, Setup**, and paste the address
(`https://ntfy.sh/hearth-7f3k9q2x`); then press **Send a test notification**. A second address
and a ntfy access token (for a protected topic) are optional. A self-hosted ntfy is recognised
when its name starts with "ntfy" (e.g. `https://ntfy.example.com/hearth`).

- One message per check, listing what was raised; a problem that cleared after 5 minutes or
  more says so. At most 6 messages an hour; nothing older than an hour is sent late.
- **System, Settings** chooses warnings and problems, or problems only, and the dashboard's
  address for the link in each message (e.g. `http://192.168.1.60:8080`).
- What leaves your home: the alert text, which can name your devices ("Kitchen iPad is off the
  mesh"), and that link. Use a hard-to-guess topic, a token, or your own ntfy server.
- The addresses are kept with the passwords (`router.env`: `NOTIFY_URL=`, `NOTIFY_URL_2=`,
  `NOTIFY_TOKEN=`), are never shown back, and can only be set from the computer running Hearth.
  If sending fails, **System, Setup** and **Data sources** say why.

### Speed test

**Usage, Speed test** measures download and upload, and how much lag a full line adds — the
"bufferbloat" that makes calls stutter while someone downloads (graded A to D). It sends test
data to Cloudflare's speed test for about 20 seconds, only when you press the button (at most 4
an hour). A daily schedule can be set in `config.json` (`"speedtest_schedule": "daily 03:00"`);
it's off by default and can't be set from the page.

## Optional extras

**System, Setup** shows which of these Hearth found and what each needs.

### Your router (GL.iNet)

With a GL.iNet router (firmware 4.x), Hearth shows **who uses the internet** — speeds now, totals
for any range, today, the month — plus the router's temperature, load and restarts, its internet
connection (PPPoE or DHCP, its address, and each reconnection as an event) and its traffic shaping
(SQM), which the speed test mentions because a test can't measure past it.

Give Hearth the router's admin password: open the dashboard **on the computer running Hearth**
and use **System, Setup**, or put it in `%USERPROFILE%\.hearth\router.env` (Linux:
`~/.hearth/router.env`, or set `router_credentials_file`):

```ini
GLINET_PASSWORD=your-router-admin-password
```

The password is used only to log in to the router on your network. It's never logged, shown or
sent anywhere else, and it can only be set from the computer running Hearth.

### Your mesh (TP-Link Deco)

Ping timing can't see which mesh unit a device is on. With TP-Link Deco units, Hearth reads the
real layout — which unit each device is on, by cable or which band, and every link's signal —
and names the real link in each slowdown ("Office mesh node or its wireless link to Bedroom").
Add the password the Deco app uses, the same way as the router's (Setup, or the same file):

```ini
DECO_PASSWORD=your-deco-password
```

The login is read-only, and the password only leaves this computer encrypted inside the Deco's
own login. Hearth recognises the main unit by its keys and refuses to log in to anything else;
if a unit is reset or replaced it asks you to confirm on the Network tab. Set
`"mesh_auto_trust": false` in `config.json` to be asked about every new certificate too.
Devices the mesh doesn't list (some wired ones behind a switch) are placed by their reply times,
marked "probably", or left under **Location unknown** when Hearth can't tell.

### UPnP

If your router answers UPnP, Hearth reads its own traffic counters (totals, no per-device split)
and public address. Nothing to set up; turn it off with `"upnp": false`.

### Home Assistant

[homeassistant/hearth_sensors.yaml](homeassistant/hearth_sensors.yaml) adds Hearth's status to
Home Assistant: the one-sentence verdict, internet up/down, latency, loss, today's use, alerts
active and the latest alert, the weekly digest's headline, and more. Notify from them with an
automation. The folder also has a script to run Home Assistant as a Hyper-V VM on the same
computer.

## Settings

**In the page** (System, Settings): the day your usage month starts, which DNS resolvers to
check, the name the DNS check looks up, which kinds of alert you get, which levels are sent as
notifications, and the dashboard's address for their link. Saved straight away.

**In `config.json`** (in this folder; all optional, defaults and descriptions in
[hearth/config.py](hearth/config.py)), for install-time things: `web_port`, `internet_targets`,
`exclude_ips`, `discovery_subnet` (if Hearth picks the wrong network), `device_interval_s`,
`notify_level` and `dashboard_url` (defaults for the page settings above),
`speedtest_schedule`, `speedtest_server`, `mesh_auto_trust`, `upnp`. Restart Hearth after
editing it.

## Security

The dashboard has **no login**, like most home dashboards: run it only on your home network and
**never forward its port to the internet** (use a VPN or Home Assistant's remote access).
Don't put it behind a reverse proxy on the same computer either: Hearth trusts requests from the
computer itself to set the router and mesh passwords.

What the page can change is small and checked on the server: names (✎), the settings above,
marking alerts seen, starting a speed test (rate-limited), sending a test notification (once a
minute, to your own channels), confirming a changed mesh unit, and — only from the computer
running Hearth — the router and mesh passwords and the notification addresses. Every write
requires the page's own origin, so another website can't make your browser do it. Hearth sends
pings, a traceroute, a DNS question a minute to the resolvers you allow, speed tests you start,
notifications to the addresses you set, and (with the extras) reads your router and mesh. It
never changes a device or a setting on them.

## Storage and resources

Everything is in `hearth.db` in this folder. Per-second pings are kept 48 hours; per-minute
summaries, slowdowns and outages, and hourly usage 400 days; events, DNS checks and alerts 90
days; weekly digests a year; speed test results (a few dozen bytes each) for good — about 50 MB a
year in all. Delete the file to start fresh.

**Backups:** each night (03:30) Hearth copies `hearth.db` into `backups/hearth-YYYY-MM-DD.db.gz`,
checked and compressed (about a third of the size), keeping the last 7. **System, Data sources**
shows the latest. In `config.json`: `backup_keep` (0 turns them off), `backup_dir` (another disk is
safer) and `backup_time`. To restore: stop Hearth, unzip a backup (7-Zip, or `gzip -d`) to
`hearth.db` in this folder, delete `hearth.db-wal` and `hearth.db-shm` if present, start Hearth.

Idle cost is small: a few percent of one CPU core and about 100 MB of memory. Long ranges are
read from the summaries, and every view is cached briefly and shared between open pages.

## Troubleshooting

- **The page doesn't open from another device:** allow Hearth (Python) through the firewall on
  private networks, and use the computer's address, not `localhost`.
- **"Isn't getting replies from the internet":** this computer is offline, or a firewall blocks
  ping (ICMP).
- **Wrong network, or no devices:** set `discovery_subnet` in `config.json`, e.g.
  `"192.168.1.0/24"`.
- **Router or mesh not read:** see System, Setup and Data sources — they say what's wrong
  (password, unreachable, a changed mesh unit waiting for you).
- **The map looks odd at first:** give it five minutes to learn the layout.

## API

All `GET`s take `?minutes=N` for their range. Read-only:
`/api/status` (compact, for Home Assistant), `/api/kpi`, `/api/overview`, `/api/summary`,
`/api/series`, `/api/incidents`, `/api/events`, `/api/devices`, `/api/device/places?id=`,
`/api/mesh`, `/api/wifi`, `/api/usage`, `/api/usage/month?month=YYYY-MM`,
`/api/outages?days=7|30|90|365`, `/api/report?month=YYYY-MM`, `/api/dns`, `/api/quality`,
`/api/host`, `/api/alerts`, `/api/digest`, `/api/speedtest`, `/api/settings`, `/api/setup`,
`/api/topology`, `/api/live`.

Writes (`POST`, JSON, from the page's own origin): `/api/label`, `/api/settings`,
`/api/alerts/seen`, `/api/speedtest`, `/api/notify/test`, `/api/router/refresh`, `/api/mesh/trust`,
and `/api/setup/credentials` (only from the computer running Hearth).

## Tests

`python -m unittest discover -s tests -t .`
