"""
config.py — Centralised configuration loaded from environment variables.
All tunables live here; nothing is hardcoded elsewhere.
"""

import os

# ── Network ───────────────────────────────────────────────────────────────────
NETWORK_SUBNET   = os.getenv("NETWORK_SUBNET",  "192.168.0.0/24")
ROUTER_IP        = os.getenv("ROUTER_IP",        "192.168.0.1")
SCAN_INTERVAL    = int(os.getenv("SCAN_INTERVAL", "600"))   # seconds

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR   = "/app"
DATA_DIR   = os.path.join(BASE_DIR, "data")
LOG_DIR    = os.path.join(BASE_DIR, "logs")
DB_PATH    = os.path.join(DATA_DIR, "network.db")
LOG_PATH   = os.path.join(LOG_DIR,  "monitor.log")
EXPORT_DIR = os.path.join(DATA_DIR, "exports")

# ── Port scan list ────────────────────────────────────────────────────────────
# Covers: common services + smart TV + IoT + media + admin ports
PORT_SCAN_LIST = (
    "21,22,23,25,53,80,110,143,443,445,"   # core services
    "554,1883,3389,4444,5000,5555,5900,"   # RDP, ADB(TV), VNC, RTSP, MQTT
    "7676,8008,8009,8080,8443,8883,"       # Chromecast, HTTP alt, MQTT-SSL
    "9100,32400,49152,55000,62078"         # Printers, Plex, UPnP, Samsung TV, iOS
)

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# ── OUI lookup ────────────────────────────────────────────────────────────────
OUI_URL        = "https://standards-oui.ieee.org/oui/oui.txt"
OUI_CACHE_PATH = os.path.join(DATA_DIR, "oui_cache.txt")

# ── Baseline ──────────────────────────────────────────────────────────────────
BASELINE_SEEN_THRESHOLD = 3

# ── Alert deduplication ───────────────────────────────────────────────────────
DEDUP_WINDOW_MINUTES = int(os.getenv("DEDUP_WINDOW_MINUTES", "30"))

# ── Healthcheck ───────────────────────────────────────────────────────────────
HEARTBEAT_PATH = os.path.join(DATA_DIR, "heartbeat")

# ── Timezone ──────────────────────────────────────────────────────────────────
TZ_NAME = "Africa/Nairobi"

# ── Scan threading ────────────────────────────────────────────────────────────
# Max parallel device scans — keeps total scan time bounded
SCAN_THREADS = int(os.getenv("SCAN_THREADS", "4"))
