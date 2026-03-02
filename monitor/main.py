"""
main.py — Entry point for the network monitor agent.

Startup sequence
----------------
1. Create data/log directories (must be first — before logging)
2. Configure logging
3. Initialise SQLite database
4. Download / load OUI vendor database
5. Run one immediate scan
6. Schedule recurring scans every SCAN_INTERVAL seconds
7. Block forever on the scheduler loop

Graceful shutdown on SIGINT / SIGTERM.
"""

import logging
import os
import signal
import sys
import time
from datetime import datetime
from monitor.timeutil import now_iso, now_display

import schedule

from monitor.config import SCAN_INTERVAL, DATA_DIR, LOG_DIR, EXPORT_DIR, HEARTBEAT_PATH

log = logging.getLogger(__name__)

# Global state — tracks which MACs were online in the previous scan
_previously_online: set[str] = set()
_running = True


def _handle_signal(signum, frame):
    global _running
    log.info("Shutdown signal received (%s) — stopping gracefully…", signum)
    _running = False


def run_scan():
    """Execute one full scan cycle."""
    global _previously_online

    from monitor import db
    from monitor.scanner import scan_network
    from monitor.detector import process_scan
    from monitor.reporter import print_scan_summary

    log.info("Starting scan cycle…")
    scan_id = db.start_scan()

    results = scan_network()

    summary = process_scan(
        scan_id=scan_id,
        current_results=results,
        previously_online_macs=_previously_online,
    )

    _previously_online = {r.mac for r in results}

    db.finish_scan(
        scan_id=scan_id,
        devices_found=len(results),
        new_devices=summary["new_devices"],
        offline_devices=summary["offline_devices"],
        alerts_raised=summary["alerts_raised"],
    )

    print_scan_summary(summary, total_online=len(results))

    # Write heartbeat so Docker healthcheck can verify the loop is alive
    try:
        with open(HEARTBEAT_PATH, "w") as f:
            f.write(now_iso())
    except Exception:
        pass

    return summary


def run_daily_export():
    from monitor.reporter import export_csv_snapshot
    path = export_csv_snapshot()
    log.info("Daily CSV export saved: %s", path)


def main():
    # ── 1. Directories FIRST — before anything tries to write a file ──────────
    for d in (DATA_DIR, LOG_DIR, EXPORT_DIR):
        os.makedirs(d, exist_ok=True)

    # ── 2. Logging (now safe — log dir exists) ────────────────────────────────
    from monitor.logger import setup_logging
    setup_logging()

    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    log.info("  Home Network Monitor — Phase 1")
    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    # ── 3. Graceful shutdown hooks ────────────────────────────────────────────
    signal.signal(signal.SIGINT,  _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    # ── 4. Init database ──────────────────────────────────────────────────────
    from monitor import db
    db.init_db()

    # ── 5. Load OUI vendor database ───────────────────────────────────────────
    from monitor.oui import ensure_oui_ready
    ensure_oui_ready()

    # ── 6. First scan immediately on startup ──────────────────────────────────
    log.info("Running initial scan…")
    run_scan()

    from monitor.reporter import print_device_table
    print_device_table()

    # ── 7. Schedule recurring scans ───────────────────────────────────────────
    log.info("Scan interval: %d seconds (change SCAN_INTERVAL in .env + restart)", SCAN_INTERVAL)
    schedule.every(SCAN_INTERVAL).seconds.do(run_scan)
    schedule.every().day.at("06:00").do(run_daily_export)

    # ── 8. Main loop ──────────────────────────────────────────────────────────
    while _running:
        schedule.run_pending()
        time.sleep(1)


if __name__ == "__main__":
    main()
