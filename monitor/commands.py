"""
commands.py — Telegram command handlers.
"""

import logging
import os
import time

from monitor.telegram_bot import authorised
from monitor import formatter
from monitor.config import HEARTBEAT_PATH, TELEGRAM_CHAT_ID

log = logging.getLogger(__name__)


@authorised
async def cmd_start(update, context):
    await update.message.reply_text(formatter.help_message(), parse_mode="HTML")


@authorised
async def cmd_help(update, context):
    await update.message.reply_text(formatter.help_message(), parse_mode="HTML")


@authorised
async def cmd_devices(update, context):
    await update.message.reply_text(formatter.devices_message(), parse_mode="HTML")


@authorised
async def cmd_alerts(update, context):
    await update.message.reply_text(formatter.alerts_message(limit=10), parse_mode="HTML")


@authorised
async def cmd_stats(update, context):
    await update.message.reply_text(formatter.stats_message(), parse_mode="HTML")


@authorised
async def cmd_ports(update, context):
    if not context.args:
        await update.message.reply_text(
            "Usage: /ports &lt;ip or mac&gt;\nExample: /ports 192.168.0.1",
            parse_mode="HTML"
        )
        return
    await update.message.reply_text(
        formatter.ports_message(context.args[0]), parse_mode="HTML"
    )


@authorised
async def cmd_whois(update, context):
    if not context.args:
        await update.message.reply_text(
            "Usage: /whois &lt;ip or mac&gt;\nExample: /whois 192.168.0.102",
            parse_mode="HTML"
        )
        return
    await update.message.reply_text(
        formatter.whois_message(context.args[0]), parse_mode="HTML"
    )


@authorised
async def cmd_scan(update, context):
    """Trigger an immediate scan and report full results."""
    await update.message.reply_text("🔍 Triggering scan now…", parse_mode="HTML")
    try:
        import asyncio
        from monitor.main import run_scan
        loop    = asyncio.get_event_loop()
        summary = await loop.run_in_executor(None, run_scan)

        online  = summary.get("online_count", 0)
        new     = summary.get("new_devices", 0)
        back    = summary.get("online_returns", 0)
        offline = summary.get("offline_devices", 0)
        alerts  = summary.get("alerts_raised", 0)

        lines = ["✅ <b>Scan Complete</b>\n"]
        lines.append(f"  Online now : {online}")
        lines.append(f"  New        : {new}")
        lines.append(f"  Back online: {back}")
        lines.append(f"  Offline    : {offline}")
        lines.append(f"  Alerts     : {alerts}")

        await update.message.reply_text("\n".join(lines), parse_mode="HTML")

    except Exception as e:
        log.error("Manual scan failed: %s", e)
        await update.message.reply_text(
            f"❌ Scan failed: {str(e)[:200]}", parse_mode="HTML"
        )


@authorised
async def cmd_health(update, context):
    """Check monitor health — shows stalled/down state if heartbeat is old."""
    age          = _get_heartbeat_age()
    last_scan_at = _get_last_scan_at()
    device_count = _get_device_count()
    await update.message.reply_text(
        formatter.health_message(age, last_scan_at, device_count),
        parse_mode="HTML"
    )


@authorised
async def cmd_label(update, context):
    """
    /label <ip> <name>   — set a friendly label
    /label <ip> -        — clear the label
    """
    args = context.args
    if len(args) < 2:
        await update.message.reply_text(
            "Usage:\n"
            "/label &lt;ip&gt; &lt;name&gt;  — label a device\n"
            "/label &lt;ip&gt; -        — clear label\n\n"
            "Example: /label 192.168.0.102 Eliot's TV",
            parse_mode="HTML"
        )
        return

    ip    = args[0]
    label = " ".join(args[1:]).strip()
    clear = label == "-"
    if clear:
        label = ""

    # Validate label length
    if len(label) > 32:
        await update.message.reply_text(
            "❌ Label too long — maximum 32 characters."
        )
        return

    from monitor import db, formatter
    device = db.get_device_by_ip(ip)
    if not device:
        await update.message.reply_text(
            f"❌ No device found with IP <code>{_esc(ip)}</code>\n"
            f"Use /devices to see known IPs.",
            parse_mode="HTML"
        )
        return

    db.set_label(device["mac"], label)
    # Re-fetch so the response shows the updated state
    device = db.get_device(device["mac"])
    await update.message.reply_text(
        formatter.label_message(ip, label, device),
        parse_mode="HTML"
    )


def _esc(text: str) -> str:
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


async def unknown_command(update, context):
    if str(update.effective_chat.id) != str(TELEGRAM_CHAT_ID):
        return
    await update.message.reply_text(
        "Unknown command. Type /help for the command list."
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_heartbeat_age() -> float:
    try:
        return time.time() - os.path.getmtime(HEARTBEAT_PATH)
    except Exception:
        return float("inf")   # file missing → treat as infinitely stale


def _get_last_scan_at() -> str:
    from monitor import db
    with db.get_conn() as conn:
        row = conn.execute(
            "SELECT started_at FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
    return row[0] if row else ""


def _get_device_count() -> int:
    from monitor import db
    with db.get_conn() as conn:
        row = conn.execute("SELECT COUNT(*) FROM devices").fetchone()
    return row[0] if row else 0
