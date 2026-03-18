# Home Network Monitor

A self-hosted network monitoring agent that runs in Docker, scans your LAN
continuously, and delivers real-time security alerts to your Telegram.

---

## Features

### Core (Phase 1)
- **ARP + nmap discovery** — finds every device on your subnet each scan cycle
- **Parallel scanning** — configurable thread pool for fast scans across all devices
- **Port detection** — scans 25 common service ports per device with service version info
- **OS fingerprinting** — nmap `-O` with conservative update policy (no flip-flopping)
- **OUI vendor lookup** — offline IEEE database with API fallback for unknown MACs
- **Baseline learning** — devices graduate from "new" to "known" after 3 sightings
- **Alert deduplication** — 30-minute window prevents repeated alerts for the same event
- **Daily CSV export** — snapshot of all devices exported automatically at 06:00
- **Host self-detection** — monitor's own container correctly identified and marked
- **Rotating logs** — 5 MB × 3 files, console + file with colour via rich
- **CLI tool** — query devices, alerts, stats, and health directly from the host

### Telegram Bot (Phase 2)
- **Real-time alerts** — new device, device offline, device back online, new port opened
- **Flood guard** — sliding-window rate limiter prevents alert storms
- **Dead man's switch** — alive ping every N hours; silence means the agent is down
- **Stalled scan detection** — auto-alert if the scan loop freezes mid-run
- **Device labelling** — tag any device with a friendly name via `/label`
- **9 bot commands** — full visibility and control from your phone
- **Daily summary** — pushed to Telegram at 06:00 with overnight digest

### Hardening
- **Log masking** — `SensitiveFilter` scrubs Telegram token and chat ID from all logs
- **httpx/telegram silenced** — library loggers suppressed to prevent token leaking via URLs
- **DB integrity check** — `PRAGMA quick_check` at every startup
- **Nightly DB cleanup** — purges `scan_events` older than 30 days (configurable)
- **`.env` chmod 600** — enforced programmatically on every startup
- **WAL mode** — concurrent read/write safe; host CLI and container don't conflict
- **Busy timeout** — 5-second SQLite retry instead of immediate lock failure

---

## Requirements

- Docker + Docker Compose
- Linux host (tested on Kali); container runs as root for `nmap -O`
- A Telegram bot token and your chat ID (see [Setup](#setup))

---

## Project Structure

```
network-monitor/
├── monitor/
│   ├── main.py          # Entry point, scheduler, lifecycle
│   ├── scanner.py       # ARP discovery + nmap port/OS scanning
│   ├── detector.py      # Alert logic: new device, offline, ports
│   ├── db.py            # All SQLite interactions
│   ├── config.py        # All settings from environment variables
│   ├── formatter.py     # Telegram HTML message builders
│   ├── telegram_bot.py  # Bot lifecycle, send bridge, flood guard
│   ├── commands.py      # All /command handlers
│   ├── reporter.py      # CLI table rendering
│   ├── logger.py        # Logging setup + SensitiveFilter
│   ├── oui.py           # OUI vendor lookup
│   └── timeutil.py      # Timezone-aware time helpers
├── scripts/
│   └── build_oui_db.py  # One-time OUI database builder
├── cli.py               # Host-side CLI tool
├── Dockerfile
├── docker-compose.yml
├── entrypoint.sh
├── requirements.txt
└── .env                 # Your config (never commit this)
```

---

## Setup

### 1. Clone and configure

```bash
git clone <your-repo> network-monitor
cd network-monitor
cp .env.example .env
chmod 600 .env
```

### 2. Create a Telegram bot

1. Message [@BotFather](https://t.me/BotFather) on Telegram
2. Send `/newbot` and follow the prompts
3. Copy the token BotFather gives you
4. Start a chat with your new bot, then visit:
   `https://api.telegram.org/bot<TOKEN>/getUpdates`
5. Send any message to the bot, refresh the URL, and copy your `chat.id`

### 3. Edit `.env`

```env
# Network
NETWORK_SUBNET=192.168.0.0/24
ROUTER_IP=192.168.0.1
SCAN_INTERVAL=60               # seconds between scans

# Telegram
TELEGRAM_TOKEN=your_token_here
TELEGRAM_CHAT_ID=your_chat_id_here
ALERT_FLOOD_LIMIT=5            # max alerts per 60s

# Tuning
LOG_LEVEL=INFO
DEDUP_WINDOW_MINUTES=30
SCAN_THREADS=4
ALIVE_PING_HOURS=6             # proof-of-life ping interval (0 = off)
SCAN_EVENTS_RETAIN_DAYS=30     # days of scan history to keep
```

### 4. Build and run

```bash
docker compose up -d --build
docker compose logs -f
```

On first start the monitor will:
1. Run an integrity check on the database
2. Build the OUI vendor database if missing
3. Run an initial scan and print a device table
4. Send a startup message to your Telegram
5. Begin the scheduled scan loop

---

## Telegram Commands

| Command | Description |
|---|---|
| `/devices` | All known devices with online/offline status |
| `/alerts` | Last 10 alerts |
| `/stats` | Scan count, device counts, alert summary |
| `/ports <ip>` | Open ports for a specific device |
| `/whois <ip>` | Full device detail including OS, vendor, label |
| `/label <ip> <name>` | Tag a device with a friendly name |
| `/label <ip> -` | Clear a device label |
| `/scan` | Trigger an immediate scan |
| `/health` | Monitor heartbeat and scan loop status |
| `/help` | Command reference |

### Device labelling

When a new device is detected you'll get:

```
🚨 New Device Detected

MAC      38:BE:AB:B0:88:B0
IP       192.168.0.102
Vendor   AltoBeam (China)
Ports    5555/tcp(adb)

Use /label 192.168.0.102 <name> to label this device
```

Run `/label 192.168.0.102 Eliot's TV` and from that point all alerts and
commands will use the friendly name instead of the vendor string.

Label display priority: **user label → hostname → vendor + IP → MAC**

---

## CLI Tool

Run directly on the host (reads the shared SQLite database):

```bash
python3 cli.py devices    # device table with status
python3 cli.py alerts     # recent alerts
python3 cli.py stats      # summary statistics
python3 cli.py export     # write CSV snapshot to data/exports/
python3 cli.py health     # heartbeat age and scan loop status
```

---

## Alerts

| Alert | Trigger | Severity |
|---|---|---|
| 🚨 New Device | Unknown MAC appears on network | WARNING |
| 📴 Device Offline | Known device absent from scan | INFO |
| ✅ Device Back Online | Previously offline device returns | INFO |
| ⚠️ New Port Opened | Port open that wasn't open last scan | WARNING |
| 🔴 Monitor Stalled | Scan loop heartbeat missed 3× interval | ERROR |

All alerts are deduplicated within a 30-minute window per device.
A configurable flood guard limits total alerts to `ALERT_FLOOD_LIMIT` per 60 seconds.

### Dead man's switch

Every `ALIVE_PING_HOURS` hours the bot sends:

```
✅ Monitor Alive

Online    : 3 / 4 devices
Last scan : 2026-03-05 17:32:14

Next check-in in 6h. If this stops arriving, the agent is down.
```

If that message stops arriving, Docker has crashed and the bot can't alert you.
No external watchdog script is needed — silence is the signal.

---

## Data

| Path | Contents |
|---|---|
| `data/network.db` | Main SQLite database |
| `data/oui.db` | IEEE OUI vendor database |
| `data/heartbeat` | Timestamp of last successful scan |
| `data/exports/` | Daily CSV snapshots |
| `logs/monitor.log` | Rotating application log (5 MB × 3) |

The database retains the last 30 days of `scan_events` history. Device records
and alert history are kept indefinitely. Adjust `SCAN_EVENTS_RETAIN_DAYS` in
`.env` to change the retention window.

---

## Security Notes

- Container runs as **root** — required for `nmap -O` raw socket access
- Capabilities are locked to `NET_ADMIN` and `NET_RAW` only via `docker-compose.yml`
- `no-new-privileges: true` is set — no privilege escalation possible
- `.env` is enforced `chmod 600` on every startup
- Telegram token and chat ID are **never written to logs** — `SensitiveFilter`
  scrubs them from all log records at the handler level before writing
- `httpx` and `telegram` library loggers are silenced to WARNING to prevent
  token leaking via HTTP request URL logs
- Bot ignores all messages from chat IDs not matching `TELEGRAM_CHAT_ID`
- nmap port arguments are validated (digit + range check) before shell use

---

## Troubleshooting

**Bot not responding**
```bash
docker compose logs -f | grep -i telegram
```
Check that `TELEGRAM_TOKEN` and `TELEGRAM_CHAT_ID` are correctly set in `.env`.

**CLI reports `unable to open database file`**
```bash
sudo chmod 755 data/
sudo chmod 644 data/network.db
```
Then retry. This happens if Docker recreated the data directory as root with
restrictive permissions.

**OS shows as Unknown for all devices**
The container must run as root for `nmap -O`. Confirm with:
```bash
docker compose exec network-monitor whoami   # should print: root
```

**DB corruption after unclean shutdown**
```bash
docker compose down
python3 -c "
import sqlite3; conn = sqlite3.connect('data/network.db')
conn.execute('PRAGMA wal_checkpoint(TRUNCATE)'); conn.close()
print('OK')
"
docker compose up -d
```

---

## Roadmap

- [x] Phase 1 — Core scanning, detection, alerts, CLI
- [x] Phase 2 — Telegram bot, real-time alerts, commands, labelling, hardening
- [ ] Phase 3 — Web dashboard (in progress)
