# Home Network Monitor — Phase 1

A self-contained, Dockerised Python agent that continuously maps your home
network, tracks every device (by MAC address), detects anomalies, and logs
everything to a local SQLite database.

---

## What it does

| Feature | Detail |
|---|---|
| Host discovery | ARP ping sweep of `192.168.0.0/24` every 60 seconds |
| Port scanning | Checks 15 common ports per device |
| Vendor lookup | IEEE OUI database maps MACs to manufacturer names |
| Anomaly detection | Alerts on new devices, offline known devices, new open ports |
| Persistent storage | SQLite database in `./data/network.db` |
| Rotating logs | Up to 15 MB of logs in `./logs/` |
| Daily CSV export | Snapshot of all devices at 06:00 UTC each day |

---

## Prerequisites

```bash
# Docker and Docker Compose
sudo apt update
sudo apt install -y docker.io docker-compose-plugin

# Add your user to the docker group (log out and back in after this)
sudo usermod -aG docker $USER
```

---

## Setup — Step by Step

### Step 1 — Get the project

```bash
mkdir -p ~/projects
cd ~/projects
# If you have git:
# git clone <your-repo> network-monitor && cd network-monitor

# Or just create the folder and copy the files in:
mkdir network-monitor && cd network-monitor
```

### Step 2 — Review configuration

Open `.env` and confirm your settings:

```bash
nano .env
```

```
NETWORK_SUBNET=192.168.0.0/24   # Your network range
ROUTER_IP=192.168.0.1            # Your router IP
SCAN_INTERVAL=60                 # Seconds between scans
LOG_LEVEL=INFO
```

### Step 3 — Build the Docker image

```bash
docker compose build
```

This will:
- Pull `python:3.12-slim`
- Install `nmap`, `arp-scan`, and Python dependencies
- Copy the monitor code into the image

Expected output ends with: `Successfully built ...`

### Step 4 — Start the monitor

```bash
docker compose up -d
```

The `-d` flag runs it in the background.

### Step 5 — Watch it run

```bash
# Follow live logs
docker compose logs -f

# Or just the last 50 lines
docker compose logs --tail=50
```

On first run you will see:
1. OUI database download (~5 MB, one time only)
2. Initial scan running
3. Device table printed with everything found
4. Recurring scan scheduled

---

## Querying the database

Use the CLI tool from the project directory on your host machine:

```bash
# Install dependencies locally (or just use pip in a venv)
pip install rich

# Show all known devices
python cli.py devices

# Show recent alerts
python cli.py alerts

# Show statistics
python cli.py stats

# Export devices to CSV
python cli.py export
```

Or query SQLite directly:

```bash
sqlite3 data/network.db

# Some useful queries:
.headers on
.mode column

-- All devices seen
SELECT mac, vendor, hostname, times_seen, last_seen FROM devices ORDER BY last_seen DESC;

-- New devices from the last hour
SELECT mac, vendor, hostname, first_seen FROM devices
WHERE first_seen > datetime('now', '-1 hour');

-- All WARNING+ alerts
SELECT created_at, alert_type, mac, detail FROM alerts
WHERE severity != 'INFO' ORDER BY created_at DESC;

-- Scan history
SELECT id, started_at, devices_found, new_devices, alerts_raised FROM scans
ORDER BY id DESC LIMIT 20;

.quit
```

---

## Stopping and restarting

```bash
# Stop (data is preserved in ./data)
docker compose down

# Restart
docker compose up -d

# Full rebuild after code changes
docker compose down && docker compose build && docker compose up -d
```

---

## Project structure

```
network-monitor/
├── docker-compose.yml       # Service definitions
├── Dockerfile               # Container build instructions
├── requirements.txt         # Python dependencies
├── .env                     # Your configuration (not committed to git)
├── .gitignore
├── cli.py                   # Host-side query tool
├── monitor/
│   ├── __init__.py
│   ├── main.py              # Entry point + scan loop
│   ├── config.py            # All configuration constants
│   ├── scanner.py           # nmap-based network scanning
│   ├── detector.py          # Anomaly detection logic
│   ├── db.py                # SQLite read/write
│   ├── oui.py               # MAC → vendor lookup
│   ├── reporter.py          # Console tables + CSV export
│   └── logger.py            # Logging setup
├── data/                    # Created at runtime (gitignored)
│   ├── network.db           # SQLite database
│   ├── oui_cache.txt        # IEEE OUI database (cached)
│   └── exports/             # Daily CSV snapshots
└── logs/                    # Created at runtime (gitignored)
    └── monitor.log
```

---

## Troubleshooting

**Permission denied / can't scan:**
The container needs `NET_ADMIN` and `NET_RAW` capabilities and `network_mode: host`.
These are already set in `docker-compose.yml`. If nmap still fails, ensure Docker
is not in rootless mode, or run:
```bash
sudo docker compose up -d
```

**No devices found:**
- Confirm `NETWORK_SUBNET` matches your router's subnet
- Run `ip route` on your Linux host to see the correct subnet
- Try `nmap -sn 192.168.0.0/24` directly on the host to verify nmap works

**OUI download fails:**
Network is unavailable from the container. The monitor will still run but
vendor names will show as "Unknown". The file will be downloaded on the next
restart when network is available.

**Database locked errors:**
Unlikely but if they occur, stop the container and run:
```bash
sqlite3 data/network.db "PRAGMA integrity_check;"
```

---

## What's coming in Phase 2

- Telegram bot for real-time alerts on your phone
- `/devices`, `/status`, `/alerts`, `/scan` commands via Telegram
- Alert deduplication to prevent notification spam
