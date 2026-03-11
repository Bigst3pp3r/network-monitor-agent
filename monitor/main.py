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


def _check_stalled():
    """
    Push a stalled alert if the heartbeat file hasn't been updated in
    3× the scan interval. Distinct from the alive ping — this fires when
    the container is running but the scan loop itself has frozen.
    """
    try:
        age = time.time() - os.path.getmtime(HEARTBEAT_PATH)
    except FileNotFoundError:
        return  # not yet written — agent just started
    except Exception:
        return

    stale_threshold = SCAN_INTERVAL * 3
    if age > stale_threshold:
        log.error("Scan loop stalled — heartbeat age %.0fs > threshold %.0fs",
                  age, stale_threshold)
        try:
            from monitor.telegram_bot import get_bot
            from monitor import formatter
            bot = get_bot()
            if bot:
                bot.send_message(formatter.alert_stalled())
        except Exception as e:
            log.warning("Failed to push stalled alert: %s", e)


def _run_db_cleanup():
    """
    Purge old scan_events rows to prevent unbounded DB growth.
    At 60s interval with 4 devices: ~1440 rows/device/day → ~2M rows/year.
    Keeps the last SCAN_EVENTS_RETAIN_DAYS days of data (default 30).
    """
    from monitor import db
    from monitor.config import SCAN_EVENTS_RETAIN_DAYS
    try:
        deleted = db.purge_old_scan_events(SCAN_EVENTS_RETAIN_DAYS)
        if deleted:
            log.info("DB cleanup: removed %d old scan_event rows (>%dd)",
                     deleted, SCAN_EVENTS_RETAIN_DAYS)
    except Exception as e:
        log.warning("DB cleanup failed: %s", e)


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

    from monitor.logger import setup_logging, sensitive_filter
    setup_logging()

    # Activate log scrubbing — must happen immediately after logging is set up
    # so no subsequent log call can emit the raw token or chat_id
    from monitor.config import TELEGRAM_TOKEN, TELEGRAM_CHAT_ID
    sensitive_filter.configure(TELEGRAM_TOKEN, TELEGRAM_CHAT_ID)

    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    log.info("  Home Network Monitor — Phase 2")
    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    signal.signal(signal.SIGINT,  _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    from monitor import db
    db.init_db()

    # ── DB integrity check ────────────────────────────────────────────────────
    try:
        result = db.check_integrity()
        if result != "ok":
            log.error("DB integrity check FAILED: %s — monitor may be unreliable", result)
        else:
            log.info("DB integrity: ok")
    except Exception as e:
        log.error("DB integrity check error: %s", e)

    # ── Enforce .env permissions at runtime ───────────────────────────────────
    env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
    env_path = os.path.normpath(env_path)
    try:
        if os.path.exists(env_path):
            os.chmod(env_path, 0o600)
    except Exception as e:
        log.warning(".env chmod failed: %s", e)

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
    schedule.every().day.at("03:00").do(_run_db_cleanup)
    schedule.every(2).minutes.do(_check_stalled)

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
