"""
main.py — Entry point for the network monitor agent.
"""

import logging
import os
import signal
import sys
import time

import schedule

from monitor.config import (
    SCAN_INTERVAL, DATA_DIR, LOG_DIR, EXPORT_DIR,
    HEARTBEAT_PATH, NETWORK_SUBNET,
)
from monitor.timeutil import now_iso

log = logging.getLogger(__name__)

_previously_online: set[str] = set()
_running = True


def _handle_signal(signum, frame):
    global _running
    log.info("Shutdown signal received (%s) — stopping…", signum)
    _running = False


def run_scan() -> dict:
    """Execute one full scan cycle. Returns summary dict."""
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
    summary["online_count"] = len(results)

    _previously_online = {r.mac for r in results}

    db.finish_scan(
        scan_id=scan_id,
        devices_found=len(results),
        new_devices=summary["new_devices"],
        offline_devices=summary["offline_devices"],
        alerts_raised=summary["alerts_raised"],
    )

    print_scan_summary(summary, total_online=len(results))

    try:
        with open(HEARTBEAT_PATH, "w") as f:
            f.write(now_iso())
    except Exception:
        pass

    return summary


def _send_alive_ping():
    """Periodic proof-of-life push — silence means agent is down."""
    try:
        from monitor.telegram_bot import get_bot
        from monitor import formatter
        from monitor.config import ALIVE_PING_HOURS
        bot = get_bot()
        if bot:
            bot.send_message(formatter.alive_ping(ALIVE_PING_HOURS))
    except Exception as e:
        log.warning("Alive ping failed: %s", e)


def run_daily_export():
    """Export CSV and push daily summary to Telegram."""
    from monitor.reporter import export_csv_snapshot
    from monitor import formatter

    path = export_csv_snapshot()
    log.info("Daily CSV export: %s", path)

    # Push summary digest to Telegram
    try:
        from monitor.telegram_bot import get_bot
        bot = get_bot()
        if bot:
            bot.send_message(formatter.daily_summary_message())
    except Exception as e:
        log.warning("Failed to push daily summary to Telegram: %s", e)


def main():
    for d in (DATA_DIR, LOG_DIR, EXPORT_DIR):
        os.makedirs(d, exist_ok=True)

    from monitor.logger import setup_logging
    setup_logging()

    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    log.info("  Home Network Monitor — Phase 2")
    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    signal.signal(signal.SIGINT,  _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    from monitor import db
    db.init_db()

    from monitor.oui import ensure_oui_ready
    ensure_oui_ready()

    from monitor.telegram_bot import TelegramBot
    import monitor.telegram_bot as _tb_module
    bot = TelegramBot()
    bot.start()
    _tb_module._bot_instance = bot

    log.info("Running initial scan…")
    run_scan()

    from monitor.reporter import print_device_table
    print_device_table()

    from monitor import formatter
    device_count = len(db.get_all_devices())
    bot.send_message(formatter.startup_message(device_count, NETWORK_SUBNET, SCAN_INTERVAL))

    from monitor.config import ALIVE_PING_HOURS

    log.info("Scheduling scans every %d seconds", SCAN_INTERVAL)
    schedule.every(SCAN_INTERVAL).seconds.do(run_scan)
    schedule.every().day.at("06:00").do(run_daily_export)

    if ALIVE_PING_HOURS > 0:
        schedule.every(ALIVE_PING_HOURS).hours.do(_send_alive_ping)
        log.info("Alive ping every %dh — silence = agent down", ALIVE_PING_HOURS)

    while _running:
        schedule.run_pending()
        time.sleep(1)

    log.info("Shutting down…")
    bot.stop(message=formatter.shutdown_message())
    log.info("Monitor stopped cleanly.")
    sys.exit(0)


if __name__ == "__main__":
    main()
