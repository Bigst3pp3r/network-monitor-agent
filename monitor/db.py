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
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
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
            # Keep OS info if new scan has better accuracy
            existing_acc = existing["os_accuracy"] or 0
            if os_accuracy >= existing_acc and os_info:
                final_os      = os_info
                final_os_acc  = os_accuracy
            else:
                final_os      = existing["os_info"] or os_info
                final_os_acc  = existing_acc or os_accuracy
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


def get_last_known_ports(mac: str) -> set[str]:
    with get_conn() as conn:
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
