"""
detector.py — Anomaly detection with alert deduplication + Telegram push.

Alert types
-----------
new_device      — MAC never seen before
device_online   — Known device came back after being offline
device_offline  — Known device didn't respond this scan
new_port        — Device has a port open that wasn't open before
port_closed     — Previously open port is now closed (INFO only)

Offline detection strategy
--------------------------
We do NOT rely solely on the in-memory `previously_online_macs` set because
once a device goes offline it leaves that set, making it invisible to future
scans. Instead we query the DB for every known device's last scan status and
compare that against the current online set. This correctly handles:
  - Manual /scan triggered from Telegram mid-interval
  - Container restarts (in-memory state is reset, DB is ground truth)
"""

import logging
from monitor import db
from monitor.scanner import DeviceResult
from monitor.config import DEDUP_WINDOW_MINUTES
from monitor.timeutil import ago

log = logging.getLogger(__name__)


def _is_duplicate(alert_type: str, mac: str) -> bool:
    cutoff = ago(DEDUP_WINDOW_MINUTES)
    with db.get_conn() as conn:
        row = conn.execute("""
            SELECT id FROM alerts
             WHERE alert_type = ?
               AND mac        = ?
               AND created_at > ?
             LIMIT 1
        """, (alert_type, mac, cutoff)).fetchone()
    return row is not None


def _push(message: str):
    """Send alert via Telegram — never raises."""
    try:
        from monitor.telegram_bot import get_bot
        bot = get_bot()
        if bot:
            bot.send_alert(message)
    except Exception as e:
        log.debug("Telegram push failed: %s", e)


def _get_db_status_map() -> dict[str, str]:
    """
    Return {mac: 'online'|'offline'} based on each device's most recent
    scan_event. This is the ground truth for offline detection — does not
    depend on the in-memory previously_online set.
    """
    with db.get_conn() as conn:
        rows = conn.execute("""
            SELECT mac, status FROM scan_events
            WHERE id IN (
                SELECT MAX(id) FROM scan_events GROUP BY mac
            )
        """).fetchall()
    return {row["mac"]: row["status"] for row in rows}


def process_scan(scan_id: int, current_results: list[DeviceResult],
                 previously_online_macs: set[str]) -> dict:
    """
    Core detection logic — called once per scan cycle.

    Returns dict: new_devices, online_returns, offline_devices, alerts_raised
    """
    from monitor import formatter

    alerts_raised        = 0
    new_device_count     = 0
    online_return_count  = 0
    offline_device_count = 0
    current_macs         = {r.mac for r in current_results}

    # Ground-truth status from DB — used for offline detection
    db_status = _get_db_status_map()

    # ── Process each online device ────────────────────────────────────────────
    for device_result in current_results:
        mac = device_result.mac

        device = db.upsert_device(
            mac=mac,
            vendor=device_result.vendor,
            hostname=device_result.hostname,
            is_host=device_result.is_host,
            os_info=device_result.os_info,
            os_accuracy=device_result.os_accuracy,
        )

        db.record_scan_event(
            scan_id=scan_id,
            mac=mac,
            ip=device_result.ip,
            hostname=device_result.hostname,
            open_ports=device_result.open_ports,
            status="online",
        )

        # ── New device ────────────────────────────────────────────────────────
        if device["is_new"] and not device_result.is_host:
            new_device_count += 1
            detail = (
                f"New device — MAC: {mac} | IP: {device_result.ip} | "
                f"Vendor: {device_result.vendor} | "
                f"Hostname: {device_result.hostname or 'unknown'} | "
                f"Ports: {', '.join(device_result.open_ports) or 'none'}"
            )
            if not _is_duplicate("new_device", mac):
                db.record_alert("new_device", mac, device_result.ip, detail, "WARNING")
                alerts_raised += 1
                log.warning("NEW DEVICE: %s", detail)
                _push(formatter.alert_new_device(
                    mac=mac, ip=device_result.ip,
                    vendor=device_result.vendor,
                    hostname=device_result.hostname,
                    ports=device_result.open_ports,
                ))

        # ── Device back online ────────────────────────────────────────────────
        elif device["is_known"] and db_status.get(mac) == "offline":
            # Was offline in DB, now responding again
            online_return_count += 1
            detail = (
                f"Device back online — MAC: {mac} | IP: {device_result.ip} | "
                f"Vendor: {device_result.vendor} | "
                f"Ports: {', '.join(device_result.open_ports) or 'none'}"
            )
            if not _is_duplicate("device_online", mac):
                db.record_alert("device_online", mac, device_result.ip, detail, "INFO")
                alerts_raised += 1
                log.info("BACK ONLINE: %s", detail)
                _push(formatter.alert_device_online(
                    mac=mac, ip=device_result.ip,
                    vendor=device_result.vendor,
                    hostname=device_result.hostname,
                    ports=device_result.open_ports,
                    label=device.get("notes") or "",
                ))

        # ── Port changes (known, currently online devices only) ───────────────
        if device["is_known"] and db_status.get(mac) != "offline":
            # Pass scan_id so we compare against PREVIOUS scan's ports,
            # not the current one (already written to scan_events above)
            last_ports    = db.get_last_known_ports(mac, before_scan_id=scan_id)
            current_ports = set(device_result.open_ports)
            newly_opened  = current_ports - last_ports
            newly_closed  = last_ports - current_ports

            if newly_opened:
                detail = (
                    f"New port(s) on {device_result.ip} ({device_result.vendor}) "
                    f"— MAC: {mac} | New: {', '.join(sorted(newly_opened))}"
                )
                if not _is_duplicate("new_port", mac):
                    db.record_alert("new_port", mac, device_result.ip, detail, "WARNING")
                    alerts_raised += 1
                    log.warning("PORT CHANGE: %s", detail)
                    _push(formatter.alert_new_port(
                        mac=mac, ip=device_result.ip,
                        vendor=device_result.vendor,
                        new_ports=newly_opened,
                        label=device.get("notes") or "",
                    ))

            if newly_closed:
                detail = (
                    f"Port(s) closed on {device_result.ip} ({device_result.vendor}) "
                    f"— MAC: {mac} | Closed: {', '.join(sorted(newly_closed))}"
                )
                if not _is_duplicate("port_closed", mac):
                    db.record_alert("port_closed", mac, device_result.ip, detail, "INFO")
                    log.info("PORT CLOSED: %s", detail)

    # ── Offline detection — DB-based, not memory-based ────────────────────────
    # Check every known device whose last DB status was 'online' but is now absent
    all_known = db.get_all_devices()
    for device in all_known:
        mac = device["mac"]
        if not device["is_known"]:
            continue
        if mac in current_macs:
            continue  # it's online this scan
        if db_status.get(mac) != "online":
            continue  # already marked offline in DB — don't double-alert

        # Was online in DB, not seen this scan → newly offline
        offline_device_count += 1
        db.record_scan_event(
            scan_id=scan_id, mac=mac, ip="",
            hostname=device.get("hostname", ""),
            open_ports=[], status="offline",
        )
        detail = (
            f"Known device offline — MAC: {mac} | "
            f"Vendor: {device.get('vendor', 'Unknown')} | "
            f"Hostname: {device.get('hostname') or 'unknown'}"
        )
        if not _is_duplicate("device_offline", mac):
            db.record_alert("device_offline", mac, "", detail, "INFO")
            alerts_raised += 1
            log.info("OFFLINE: %s", detail)
            _push(formatter.alert_device_offline(
                mac=mac,
                vendor=device.get("vendor", "Unknown"),
                hostname=device.get("hostname", ""),
                label=device.get("notes") or "",
            ))

    return {
        "new_devices":     new_device_count,
        "online_returns":  online_return_count,
        "offline_devices": offline_device_count,
        "alerts_raised":   alerts_raised,
    }
