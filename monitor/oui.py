"""
oui.py — MAC address manufacturer lookup via local SQLite OUI database.

Lookup priority
---------------
1. SQLite OUI database  (data/oui.db)  — fast, offline, 30 000+ entries
2. Built-in table                      — ~60 common home device prefixes
3. macvendors.com API                  — per-device, rate-limited, cached

The SQLite database is built once by running:
    python3 scripts/build_oui_db.py
on the Linux host. It is then mounted into the container via docker-compose.
"""

import os
import json
import logging
import sqlite3
import time
from monitor.config import DATA_DIR

log = logging.getLogger(__name__)

OUI_DB_PATH      = os.path.join(DATA_DIR, "oui.db")
_API_CACHE_FILE  = os.path.join(DATA_DIR, "oui_api_cache.json")

_mem_table: dict[str, str] = {}
_api_cache: dict[str, str] = {}
_db_available = False

# ── Built-in fallback ─────────────────────────────────────────────────────────
_BUILTIN: dict[str, str] = {
    "A4C361":"Apple","F0B479":"Apple","3C2EFF":"Apple","BC9FEF":"Apple",
    "685B35":"Apple","A8BE27":"Apple","ACDE48":"Apple","F0DCE2":"Apple",
    "8C7712":"Samsung","F4F951":"Samsung","4C3488":"Samsung","CC07AB":"Samsung",
    "F4F5E8":"Google","54607E":"Google","3C5AB4":"Google",
    "D83060":"Google Nest","A47733":"Google Nest",
    "FC65DE":"Amazon","AC63BE":"Amazon","B47C9C":"Amazon","0C8268":"Amazon Echo",
    "B827EB":"Raspberry Pi","DC3132":"Raspberry Pi","E45F01":"Raspberry Pi","DCA632":"Raspberry Pi",
    "8CAAB5":"Espressif","E89F6D":"Espressif","A020A6":"Espressif","246F28":"Espressif",
    "50C7BF":"TP-Link","B0BE76":"TP-Link","C46E1F":"TP-Link","A42BB0":"TP-Link",
    "CC2D21":"Tenda","C83A35":"Tenda","D4762C":"Tenda","1880BE":"Tenda",
    "C03F0E":"Netgear","A040A0":"Netgear","6CB0CE":"Netgear",
    "107B44":"ASUS","50465D":"ASUS","2C56DC":"ASUS",
    "F48B32":"Xiaomi","64B473":"Xiaomi","28E31F":"Xiaomi",
    "8086F2":"Intel","ACC907":"Intel",
    "001E10":"Huawei","286ED4":"Huawei","48DB50":"Huawei",
    "1C7EE5":"D-Link","B8A386":"D-Link",
    "00E04C":"Realtek","B06EBF":"Realtek",
    "0009BF":"Nintendo","002659":"Nintendo","8C56C5":"Nintendo",
    "0013A9":"Sony","001A80":"Sony","C86000":"Sony",
}


def _load_oui_db() -> bool:
    global _mem_table, _db_available
    if not os.path.exists(OUI_DB_PATH):
        log.warning(
            "OUI database not found at %s — run: python3 scripts/build_oui_db.py",
            OUI_DB_PATH,
        )
        return False
    try:
        conn = sqlite3.connect(OUI_DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            meta = {r["key"]: r["value"] for r in conn.execute("SELECT key,value FROM meta")}
            log.info("OUI DB: %s entries | source=%s | built=%s",
                     meta.get("entry_count","?"),
                     meta.get("source","?"),
                     meta.get("built_at","?"))
        except Exception:
            pass
        rows = conn.execute("SELECT prefix, vendor FROM oui").fetchall()
        conn.close()
        _mem_table = {r["prefix"]: r["vendor"] for r in rows}
        _db_available = True
        log.info("OUI table in memory: %d entries", len(_mem_table))
        return True
    except Exception as e:
        log.warning("Failed to load OUI database: %s", e)
        return False


def _load_api_cache():
    global _api_cache
    if os.path.exists(_API_CACHE_FILE):
        try:
            with open(_API_CACHE_FILE) as f:
                _api_cache = json.load(f)
        except Exception:
            _api_cache = {}


def _save_api_cache():
    try:
        with open(_API_CACHE_FILE, "w") as f:
            json.dump(_api_cache, f)
    except Exception:
        pass


def _api_lookup(prefix: str) -> str:
    if prefix in _api_cache:
        return _api_cache[prefix]
    try:
        import requests
        mac_q = f"{prefix[0:2]}:{prefix[2:4]}:{prefix[4:6]}"
        r = requests.get(
            f"https://api.macvendors.com/{mac_q}",
            timeout=5,
            headers={"User-Agent": "HomeNetworkMonitor/1.0"},
        )
        time.sleep(0.6)
        result = r.text.strip() if r.status_code == 200 else "Unknown"
        _api_cache[prefix] = result
        _save_api_cache()
        return result
    except Exception as e:
        log.debug("OUI API lookup failed for %s: %s", prefix, e)
        return ""


def get_vendor(mac: str) -> str:
    if not mac:
        return "Unknown"
    clean = mac.upper().replace(":", "").replace("-", "").replace(".", "")
    if len(clean) < 6:
        return "Unknown"
    prefix = clean[:6]

    # Detect randomised/locally-administered MACs
    try:
        if int(clean[0:2], 16) & 0x02:
            return "Randomised MAC (device privacy)"
    except ValueError:
        pass

    # 1. SQLite-backed in-memory table
    if _mem_table:
        v = _mem_table.get(prefix)
        if v:
            return v

    # 2. Built-in table
    v = _BUILTIN.get(prefix)
    if v:
        return v

    # 3. API fallback (cached)
    v = _api_lookup(prefix)
    if v and v != "Unknown":
        return v

    return "Unknown"


def db_stats() -> dict:
    return {
        "db_available": _db_available,
        "entries_in_memory": len(_mem_table),
        "api_cache_entries": len(_api_cache),
        "db_path": OUI_DB_PATH,
    }


def ensure_oui_ready():
    os.makedirs(DATA_DIR, exist_ok=True)
    _load_api_cache()
    _load_oui_db()
