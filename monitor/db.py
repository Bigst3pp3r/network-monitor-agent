"""
db.py — All SQLite interactions.

Tables
------
devices       : Every MAC ever seen, with metadata
scan_events   : One row per device per scan (IP, ports, status)
alerts        : Log of detected anomalies
scans         : One row per scan run (start time, device count)
"""

import sqlite3
import logging
from contextlib import contextmanager
from monitor.config import DB_PATH
from monitor.timeutil import now_iso

log = logging.getLogger(__name__)


# ── Connection helper ─────────────────────────────────────────────────────────

@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES,
                           timeout=10)   # wait up to 10s if DB is locked
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    # busy_timeout: retry on SQLITE_BUSY instead of failing immediately
    # critical when container writer and host CLI reader overlap
    conn.execute("PRAGMA busy_timeout=5000")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── Schema ────────────────────────────────────────────────────────────────────

def init_db():
    with get_conn() as conn:
        # WAL mode: set once here — more concurrent-friendly than DELETE journal
        # Allows readers and one writer simultaneously without blocking
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")  # safe with WAL, faster than FULL
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS devices (
                mac             TEXT PRIMARY KEY,
                vendor          TEXT,
                hostname        TEXT,
                first_seen      TEXT NOT NULL,
                last_seen       TEXT NOT NULL,
                times_seen      INTEGER DEFAULT 1,
                is_known        INTEGER DEFAULT 0,
                is_whitelisted  INTEGER DEFAULT 0,
                is_host         INTEGER DEFAULT 0,
                os_info         TEXT,
                os_accuracy     INTEGER DEFAULT 0,
                notes           TEXT
            );

            CREATE TABLE IF NOT EXISTS scan_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     INTEGER NOT NULL,
                mac         TEXT NOT NULL,
                ip          TEXT,
                hostname    TEXT,
                open_ports  TEXT,
                status      TEXT NOT NULL,
                scanned_at  TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type  TEXT NOT NULL,
                mac         TEXT,
                ip          TEXT,
                detail      TEXT,
                severity    TEXT DEFAULT 'INFO',
                created_at  TEXT NOT NULL,
                acknowledged INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS scans (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at      TEXT NOT NULL,
                finished_at     TEXT,
                devices_found   INTEGER DEFAULT 0,
                new_devices     INTEGER DEFAULT 0,
                offline_devices INTEGER DEFAULT 0,
                alerts_raised   INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_scan_events_mac  ON scan_events(mac);
            CREATE INDEX IF NOT EXISTS idx_scan_events_scan ON scan_events(scan_id);
            CREATE INDEX IF NOT EXISTS idx_alerts_type      ON alerts(alert_type);
            CREATE INDEX IF NOT EXISTS idx_alerts_created   ON alerts(created_at);
        """)

    # Migrations: add columns to databases that predate them
    with get_conn() as conn:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(devices)").fetchall()]
        if "is_host" not in cols:
            conn.execute("ALTER TABLE devices ADD COLUMN is_host INTEGER DEFAULT 0")
            log.info("Migrated devices table: added is_host column")
        if "os_info" not in cols:
            conn.execute("ALTER TABLE devices ADD COLUMN os_info TEXT")
            conn.execute("ALTER TABLE devices ADD COLUMN os_accuracy INTEGER DEFAULT 0")
            log.info("Migrated devices table: added os_info, os_accuracy columns")

    log.info("Database initialised at %s", DB_PATH)


# ── Scan helpers ──────────────────────────────────────────────────────────────

def start_scan() -> int:
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO scans (started_at) VALUES (?)", (now_iso(),)
        )
        return cur.lastrowid


def finish_scan(scan_id: int, devices_found: int, new_devices: int,
                offline_devices: int, alerts_raised: int):
    with get_conn() as conn:
        conn.execute("""
            UPDATE scans
               SET finished_at=?, devices_found=?, new_devices=?,
                   offline_devices=?, alerts_raised=?
             WHERE id=?
        """, (now_iso(), devices_found, new_devices,
              offline_devices, alerts_raised, scan_id))


# ── Device helpers ────────────────────────────────────────────────────────────

def upsert_device(mac: str, vendor: str, hostname: str,
                  is_host: bool = False,
                  os_info: str = "", os_accuracy: int = 0) -> dict:
    from monitor.config import BASELINE_SEEN_THRESHOLD
    now = now_iso()
    is_host_int = 1 if is_host else 0

    with get_conn() as conn:
        existing = conn.execute(
            "SELECT * FROM devices WHERE mac=?", (mac,)
        ).fetchone()

        if existing is None:
            conn.execute("""
                INSERT INTO devices
                    (mac, vendor, hostname, first_seen, last_seen,
                     times_seen, is_known, is_host, os_info, os_accuracy)
                VALUES (?, ?, ?, ?, ?, 1, 0, ?, ?, ?)
            """, (mac, vendor, hostname, now, now,
                  is_host_int, os_info, os_accuracy))
            is_new = True
        else:
            times_seen  = existing["times_seen"] + 1
            is_known    = 1 if times_seen >= BASELINE_SEEN_THRESHOLD else existing["is_known"]
            vendor      = vendor   or existing["vendor"]
            hostname    = hostname or existing["hostname"]
            # OS update policy:
            # Only replace stored OS if the new result is meaningfully better
            # (10+ accuracy points). nmap is not perfectly consistent scan-to-scan
            # so a small fluctuation (90% → 91%) should NOT overwrite stored data.
            # If no OS is stored yet, accept any result with accuracy > 0.
            existing_acc = existing["os_accuracy"] or 0
            existing_os  = existing["os_info"] or ""
            ACCURACY_IMPROVEMENT_THRESHOLD = 10

            if not existing_os and os_info and os_accuracy > 0:
                # Nothing stored yet — take the first valid result
                final_os, final_os_acc = os_info, os_accuracy
            elif os_info and os_accuracy >= existing_acc + ACCURACY_IMPROVEMENT_THRESHOLD:
                # New result is significantly more confident — upgrade
                final_os, final_os_acc = os_info, os_accuracy
            else:
                # Keep what we have
                final_os, final_os_acc = existing_os, existing_acc
            conn.execute("""
                UPDATE devices
                   SET last_seen=?, times_seen=?, is_known=?, is_host=?,
                       os_info=?, os_accuracy=?,
                       vendor=COALESCE(NULLIF(?, ''), vendor),
                       hostname=COALESCE(NULLIF(?, ''), hostname)
                 WHERE mac=?
            """, (now, times_seen, is_known, is_host_int,
                  final_os, final_os_acc, vendor, hostname, mac))
            is_new = False

        device = dict(conn.execute(
            "SELECT * FROM devices WHERE mac=?", (mac,)
        ).fetchone())

    device["is_new"] = is_new
    return device


def set_label(mac: str, label: str) -> bool:
    """
    Set or clear the friendly label for a device.
    label='' clears the label back to defaults.
    Returns True if the device was found and updated.
    """
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE devices SET notes=? WHERE mac=?",
            (label.strip() or None, mac)
        )
    return cur.rowcount > 0


def get_device_by_ip(ip: str) -> dict | None:
    """Find the most recently seen device with this IP."""
    with get_conn() as conn:
        row = conn.execute("""
            SELECT mac FROM scan_events
            WHERE ip = ?
            ORDER BY scanned_at DESC LIMIT 1
        """, (ip,)).fetchone()
    if not row:
        return None
    return get_device(row["mac"])


def get_all_devices() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM devices ORDER BY is_host DESC, last_seen DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def get_device(mac: str) -> dict | None:
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM devices WHERE mac=?", (mac,)
        ).fetchone()
    return dict(row) if row else None


def get_last_known_ports(mac: str, before_scan_id: int | None = None) -> set[str]:
    """
    Return the set of open ports recorded for this device in the most recent
    scan event BEFORE before_scan_id.

    Why before_scan_id: record_scan_event() for the current scan is written
    before the port-change check runs. Without this guard, get_last_known_ports
    would return the CURRENT scan's ports, making newly_opened always empty.
    """
    with get_conn() as conn:
        if before_scan_id is not None:
            row = conn.execute("""
                SELECT open_ports FROM scan_events
                 WHERE mac=? AND status='online' AND scan_id < ?
                 ORDER BY scan_id DESC LIMIT 1
            """, (mac, before_scan_id)).fetchone()
        else:
            row = conn.execute("""
                SELECT open_ports FROM scan_events
                 WHERE mac=? AND status='online'
                 ORDER BY scanned_at DESC LIMIT 1
            """, (mac,)).fetchone()
    if row and row["open_ports"]:
        return set(row["open_ports"].split(","))
    return set()


# ── Scan event helpers ────────────────────────────────────────────────────────

def record_scan_event(scan_id: int, mac: str, ip: str, hostname: str,
                      open_ports: list[str], status: str):
    ports_str = ",".join(sorted(open_ports)) if open_ports else ""
    with get_conn() as conn:
        conn.execute("""
            INSERT INTO scan_events
                (scan_id, mac, ip, hostname, open_ports, status, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (scan_id, mac, ip, hostname, ports_str, status, now_iso()))


# ── Alert helpers ─────────────────────────────────────────────────────────────

def record_alert(alert_type: str, mac: str, ip: str,
                 detail: str, severity: str = "INFO") -> int:
    with get_conn() as conn:
        cur = conn.execute("""
            INSERT INTO alerts (alert_type, mac, ip, detail, severity, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (alert_type, mac, ip, detail, severity, now_iso()))
        return cur.lastrowid


def get_recent_alerts(limit: int = 20) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?
        """, (limit,)).fetchall()
    return [dict(r) for r in rows]


# ── Export helper ─────────────────────────────────────────────────────────────

def export_devices_csv(path: str):
    import csv
    devices = get_all_devices()
    if not devices:
        return
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=devices[0].keys())
        writer.writeheader()
        writer.writerows(devices)
    log.info("Exported %d devices to %s", len(devices), path)
