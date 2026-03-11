"""
config.py — Centralised configuration loaded from environment variables.
All tunables live here; nothing is hardcoded elsewhere.
"""

import os

# ── Network ───────────────────────────────────────────────────────────────────
NETWORK_SUBNET   = os.getenv("NETWORK_SUBNET",  "192.168.0.0/24")
ROUTER_IP        = os.getenv("ROUTER_IP",        "192.168.0.1")
SCAN_INTERVAL    = int(os.getenv("SCAN_INTERVAL", "60"))   # seconds

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
    # Well-known ports
    "1,3,7,9,13,17,19,20,21,22,23,25,37,42,43,49,53,67,68,69,70,79,80,81,82,83,84,85,88,89,90,"
    "99,100,106,109,110,111,113,119,123,135,137,138,139,143,161,179,199,211,212,222,254,255,"
    
    # Common services
    "256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,"
    "481,497,500,512,513,514,515,524,541,543,544,545,548,554,563,587,593,616,617,625,631,636,"
    "646,648,666,667,668,683,687,689,691,700,705,711,714,720,722,726,749,765,777,783,787,800,"
    "801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,992,993,995,"
    
    # Application / admin / attack surface ports
    "1080,1099,1194,1214,1241,1311,1337,1433,1434,1521,1589,1645,1646,1701,1720,1723,1755,"
    "1812,1813,1863,1900,2000,2001,2049,2082,2083,2086,2087,2095,2096,2100,2222,2302,2483,2484,"
    "2601,2604,2605,2607,2608,2638,2701,2702,2710,2809,2869,3000,3001,3002,3003,3005,3050,3071,"
    "3077,3128,3168,3211,3221,3260,3268,3269,3306,3333,3389,3390,3478,3544,3632,3689,3690,3703,"
    "3986,4000,4001,4045,4443,4444,4500,4567,4662,4848,4899,"
    
    # Dev / web / containers
    "5000,5001,5002,5003,5004,5005,5006,5007,5008,5009,5050,5060,5061,5080,5087,5100,5101,"
    "5190,5222,5223,5269,5357,5358,5432,5500,5555,5601,5631,5666,5800,5801,5802,5803,"
    "5900,5901,5902,5985,5986,"
    
    # modern services
    "6000,6001,6002,6003,6004,6005,6006,6007,6346,6347,6443,6514,6566,6660,6661,6662,6663,"
    "6664,6665,6666,6667,6668,6669,6697,6881,6901,6969,7000,7001,7070,7100,7200,"
    
    # Web admin / APIs
    "7443,7474,7601,7777,7778,7800,7878,8000,8001,8002,8008,8009,8010,8011,8020,8022,8030,"
    "8042,8060,8069,8070,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,"
    
    # TLS / alt HTTPS
    "8090,8091,8098,8100,8118,8123,8180,8181,8222,8243,8280,8281,8332,8333,8383,8400,8443,"
    "8500,8530,8531,8600,8649,8686,8787,8800,8834,8880,8883,8888,"
    
    # infra / monitoring
    "9000,9001,9002,9003,9042,9060,9080,9081,9090,9091,9092,9093,9100,9160,"
    
    # misc
    "9200,9300,9418,9443,9500,9535,9600,9700,9800,9876,9898,9900,"
    
    # high ports frequently used
    "10000,10001,10010,10050,10051,10162,10250,10255,10256,10443,"
    
    # dynamic / mobile / apps
    "11000,11211,12000,12345,13720,13721,14000,15000,15672,16000,"
    
    # databases / cluster
    "17001,18080,18081,18082,20000,20001,20720,"
    
    # remote control / malware often
    "22222,25000,25565,27017,27018,27019,28017,"
    
    # streaming / gaming
    "30000,30718,31337,32768,32769,32770,32771,32772,32773,"
    
    # dynamic start
    "49152,49153,49154,49155,49156,49157,49158,49159,50000,50030,"
    "50070,50075,50090,51000,51413,52000,52869,54045,55000,55555,"
    "56789,57797,58080,60000,61000,62078,65000"
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

# ── Telegram ──────────────────────────────────────────────────────────────────
TELEGRAM_TOKEN   = os.getenv("TELEGRAM_TOKEN",   "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# Max alert messages per 60-second window (flood guard)
ALERT_FLOOD_LIMIT = int(os.getenv("ALERT_FLOOD_LIMIT", "5"))

# Hours between proof-of-life pings to Telegram (0 = disabled)
ALIVE_PING_HOURS  = int(os.getenv("ALIVE_PING_HOURS", "6"))

# Days of scan_events history to retain (older rows are purged nightly)
SCAN_EVENTS_RETAIN_DAYS = int(os.getenv("SCAN_EVENTS_RETAIN_DAYS", "30"))
