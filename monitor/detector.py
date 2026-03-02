"""
detector.py — Anomaly detection with alert deduplication.

Alert types
-----------
new_device      — MAC never seen before
device_offline  — Known device didn't respond this scan
new_port        — Device has a port open that wasn't open before
port_closed     — Previously open port is now closed (INFO only)

Deduplication
-------------
Same alert_type + MAC will not re-fire within DEDUP_WINDOW_MINUTES.
This prevents notification spam for persistent conditions (e.g. a device
that stays offline for hours generating hundreds of identical alerts).
"""

import logging
from datetime import timedelta
from monitor import db
from monitor.scanner import DeviceResult
from monitor.config import DEDUP_WINDOW_MINUTES
from monitor.timeutil import ago

log = logging.getLogger(__name__)


def _is_duplicate(alert_type: str, mac: str) -> bool:
    """
    Return True if the same alert_type+mac was already recorded
    within the deduplication window.
    """
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


def process_scan(scan_id: int, current_results: list[DeviceResult],
                 previously_online_macs: set[str]) -> dict:
    """
    Core detection logic. Called once per scan cycle.

    Parameters
    ----------
    scan_id                : ID of the current scan row in the DB
    current_results        : Live DeviceResult list from scanner
    previously_online_macs : MACs that were online in the previous scan

    Returns
    -------
    dict with keys: new_devices, offline_devices, alerts_raised
    """
    alerts_raised      = 0
    new_device_count   = 0
    offline_device_count = 0
    current_macs       = {r.mac for r in current_results}

    # ── Process each device found this scan ───────────────────────────────────
    for device_result in current_results:
        mac = device_result.mac

        # 1. Upsert into devices table
        device = db.upsert_device(
            mac=mac,
            vendor=device_result.vendor,
            hostname=device_result.hostname,
            is_host=device_result.is_host,
            os_info=device_result.os_info,
            os_accuracy=device_result.os_accuracy,
        )

        # 2. Record the scan event
        db.record_scan_event(
            scan_id=scan_id,
            mac=mac,
            ip=device_result.ip,
            hostname=device_result.hostname,
            open_ports=device_result.open_ports,
            status="online",
        )

        # 3. New device alert (skip host machine, skip duplicates)
        if device["is_new"] and not device_result.is_host:
            new_device_count += 1
            detail = (
                f"New device detected — MAC: {mac} | IP: {device_result.ip} | "
                f"Vendor: {device_result.vendor} | "
                f"Hostname: {device_result.hostname or 'unknown'} | "
                f"Open ports: {', '.join(device_result.open_ports) or 'none'}"
            )
            if not _is_duplicate("new_device", mac):
                db.record_alert("new_device", mac, device_result.ip, detail, "WARNING")
                alerts_raised += 1
                log.warning("NEW DEVICE: %s", detail)

        # 4. Port change alerts (known devices only, reduces noise)
        elif device["is_known"]:
            last_ports    = db.get_last_known_ports(mac)
            current_ports = set(device_result.open_ports)
            newly_opened  = current_ports - last_ports
            newly_closed  = last_ports - current_ports

            if newly_opened:
                detail = (
                    f"New port(s) opened on {device_result.ip} "
                    f"({device_result.vendor}) — MAC: {mac} | "
                    f"New ports: {', '.join(sorted(newly_opened))}"
                )
                if not _is_duplicate("new_port", mac):
                    db.record_alert("new_port", mac, device_result.ip, detail, "WARNING")
                    alerts_raised += 1
                    log.warning("PORT CHANGE: %s", detail)

            if newly_closed:
                detail = (
                    f"Port(s) closed on {device_result.ip} "
                    f"({device_result.vendor}) — MAC: {mac} | "
                    f"Closed: {', '.join(sorted(newly_closed))}"
                )
                if not _is_duplicate("port_closed", mac):
                    db.record_alert("port_closed", mac, device_result.ip, detail, "INFO")
                    log.info("PORT CLOSED: %s", detail)

    # ── Offline detection ─────────────────────────────────────────────────────
    offline_macs = previously_online_macs - current_macs
    for mac in offline_macs:
        device = db.get_device(mac)
        if not device or not device["is_known"]:
            continue

        offline_device_count += 1
        db.record_scan_event(
            scan_id=scan_id,
            mac=mac,
            ip="",
            hostname=device.get("hostname", ""),
            open_ports=[],
            status="offline",
        )
        detail = (
            f"Known device went offline — MAC: {mac} | "
            f"Vendor: {device.get('vendor', 'Unknown')} | "
            f"Hostname: {device.get('hostname') or 'unknown'}"
        )
        if not _is_duplicate("device_offline", mac):
            db.record_alert("device_offline", mac, "", detail, "INFO")
            alerts_raised += 1
            log.info("OFFLINE: %s", detail)

    return {
        "new_devices":      new_device_count,
        "offline_devices":  offline_device_count,
        "alerts_raised":    alerts_raised,
    }
