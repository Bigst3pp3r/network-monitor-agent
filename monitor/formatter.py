"""
formatter.py — Formats DB data into clean Telegram HTML messages.

All messages use HTML parse mode (safer than Markdown — no escaping issues
with special chars in vendor names, hostnames, port strings etc).
"""

from monitor import db


# ── Emoji constants ───────────────────────────────────────────────────────────
_ICON = {
    "new_device":    "🚨",
    "device_offline": "📴",
    "new_port":      "⚠️",
    "port_closed":   "🔒",
    "startup":       "🟢",
    "shutdown":      "🔴",
    "scan":          "🔍",
    "health_ok":     "✅",
    "health_bad":    "🔴",
    "online":        "●",
    "offline":       "○",
}

_SEVERITY_ICON = {
    "WARNING":  "⚠️",
    "CRITICAL": "🚨",
    "INFO":     "ℹ️",
}


def _esc(text: str) -> str:
    """Escape HTML special characters."""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _display_name(device: dict, ip: str = "") -> str:
    """
    Returns the best human-readable name for a device, in priority order:
      1. User label (notes field)       → "Eliot's TV"
      2. Hostname                       → "eliot-laptop"
      3. Vendor + last IP               → "Tenda 192.168.0.1"
      4. MAC                            → "38:BE:AB:B0:88:B0"
    """
    if device.get("notes"):
        return device["notes"]
    if device.get("hostname"):
        return device["hostname"]
    vendor = device.get("vendor") or ""
    if vendor and ip:
        return f"{vendor} ({ip})"
    if vendor:
        return vendor
    return device.get("mac", "Unknown")


# ── Alert messages ────────────────────────────────────────────────────────────

def alert_new_device(mac: str, ip: str, vendor: str,
                     hostname: str, ports: list[str]) -> str:
    ports_str = ", ".join(ports) if ports else "none"
    host_str  = _esc(hostname) if hostname else "unknown"
    return (
        f"🚨 <b>New Device Detected</b>\n\n"
        f"<b>MAC</b>      <code>{_esc(mac)}</code>\n"
        f"<b>IP</b>       <code>{_esc(ip)}</code>\n"
        f"<b>Vendor</b>   {_esc(vendor or 'Unknown')}\n"
        f"<b>Hostname</b> {host_str}\n"
        f"<b>Ports</b>    {_esc(ports_str)}\n\n"
        f"<i>Use /label {_esc(ip)} &lt;name&gt; to label this device</i>"
    )


def alert_device_offline(mac: str, vendor: str, hostname: str,
                         label: str = "") -> str:
    name = label or hostname or vendor or mac
    return (
        f"📴 <b>Device Offline</b>\n\n"
        f"<b>Name</b>     {_esc(name)}\n"
        f"<b>MAC</b>      <code>{_esc(mac)}</code>\n"
        f"<b>Vendor</b>   {_esc(vendor or 'Unknown')}"
    )


def alert_new_port(mac: str, ip: str, vendor: str,
                   new_ports: set[str], label: str = "") -> str:
    name = label or vendor or mac
    return (
        f"⚠️ <b>New Port Opened</b>\n\n"
        f"<b>Name</b>      {_esc(name)}\n"
        f"<b>MAC</b>       <code>{_esc(mac)}</code>\n"
        f"<b>IP</b>        <code>{_esc(ip)}</code>\n"
        f"<b>New ports</b> {_esc(', '.join(sorted(new_ports)))}"
    )


def alert_stalled() -> str:
    return (
        "🔴 <b>Monitor Stalled</b>\n\n"
        "Scan loop heartbeat missed — monitor may have crashed.\n"
        "Check container: <code>docker compose logs -f</code>"
    )


# ── Startup / shutdown ────────────────────────────────────────────────────────

def startup_message(device_count: int, subnet: str, interval: int) -> str:
    return (
        f"🟢 <b>Network Monitor Online</b>\n\n"
        f"<b>Subnet</b>    {_esc(subnet)}\n"
        f"<b>Devices</b>   {device_count} known\n"
        f"<b>Interval</b>  {interval}s\n\n"
        f"Type /help for available commands."
    )


def shutdown_message() -> str:
    return "🔴 <b>Network Monitor Offline</b>\n\nContainer is stopping."


# ── Command responses ─────────────────────────────────────────────────────────

def devices_message() -> str:
    devices        = db.get_all_devices()
    latest_scan_id = _get_latest_scan_id()
    online_macs    = _get_online_macs(latest_scan_id)

    if not devices:
        return "No devices in database yet."

    lines = ["🔍 <b>Network Devices</b>\n"]
    for d in devices:
        mac     = d["mac"]
        is_on   = mac in online_macs
        status  = "● <b>online</b>" if is_on else "○ offline"
        last_ip = _get_last_ip(mac)
        name    = _display_name(d, last_ip)
        role    = " <i>[HOST]</i>" if d.get("is_host") else ""

        lines.append(
            f"{status}{role}  <b>{_esc(name)}</b>\n"
            f"  <code>{_esc(mac)}</code>  {_esc(last_ip)}\n"
            f"  {_esc(d.get('vendor') or 'Unknown')}"
            + (f"  |  OS: {_esc(d['os_info'])}" if d.get("os_info") else "")
        )

    return "\n\n".join(lines)


def stats_message() -> str:
    with db.get_conn() as conn:
        total     = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        hosts     = conn.execute("SELECT COUNT(*) FROM devices WHERE is_host=1").fetchone()[0]
        known     = conn.execute("SELECT COUNT(*) FROM devices WHERE is_known=1").fetchone()[0]
        t_scans   = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        t_alerts  = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        t_warn    = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='WARNING'").fetchone()[0]
        last_scan = conn.execute(
            "SELECT started_at, devices_found FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()

        sid = conn.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        latest_sid = sid[0] if sid else 0
        online_ct  = conn.execute(
            "SELECT COUNT(DISTINCT mac) FROM scan_events WHERE scan_id=? AND status='online'",
            (latest_sid,)
        ).fetchone()[0]
        offline_ct = total - online_ct

    last_str = last_scan["started_at"][:19] if last_scan else "never"
    found_str = str(last_scan["devices_found"]) if last_scan else "0"

    return (
        f"📊 <b>Statistics</b>\n\n"
        f"<b>Devices</b>\n"
        f"  Total      : {total}  (host: {hosts})\n"
        f"  Known      : {known}\n"
        f"  Online now : {online_ct}\n"
        f"  Offline    : {offline_ct}\n\n"
        f"<b>Scanning</b>\n"
        f"  Scans run  : {t_scans}\n"
        f"  Last scan  : {last_str}\n"
        f"  Last count : {found_str}\n\n"
        f"<b>Alerts</b>\n"
        f"  Total      : {t_alerts}\n"
        f"  Warnings   : {t_warn}"
    )


def alerts_message(limit: int = 10) -> str:
    alerts = db.get_recent_alerts(limit)
    if not alerts:
        return "No alerts recorded yet."

    lines = [f"🔔 <b>Last {limit} Alerts</b>\n"]
    for a in alerts:
        icon = _SEVERITY_ICON.get(a["severity"], "ℹ️")
        time = a["created_at"][:19]
        lines.append(
            f"{icon} <code>{time}</code>  <b>{_esc(a['alert_type'])}</b>\n"
            f"   {_esc(a['detail'][:120])}"
        )
    return "\n\n".join(lines)


def ports_message(identifier: str) -> str:
    device, last_ip, ports = _resolve_device(identifier)

    if not device:
        return f"❌ No device found matching <code>{_esc(identifier)}</code>"

    name      = _display_name(device, last_ip)
    ports_str = "\n  ".join(ports) if ports else "none detected"
    return (
        f"🔌 <b>Open Ports</b>\n\n"
        f"<b>Name</b>   {_esc(name)}\n"
        f"<b>MAC</b>    <code>{_esc(device['mac'])}</code>\n"
        f"<b>IP</b>     <code>{_esc(last_ip)}</code>\n\n"
        f"<b>Ports</b>\n  {_esc(ports_str)}"
    )


def whois_message(identifier: str) -> str:
    device, last_ip, ports = _resolve_device(identifier)

    if not device:
        return f"❌ No device found matching <code>{_esc(identifier)}</code>"

    name      = _display_name(device, last_ip)
    os_str    = device.get("os_info") or "unknown"
    os_acc    = device.get("os_accuracy") or 0
    os_disp   = f"{os_str} ({os_acc}%)" if os_str != "unknown" else "unknown"
    ports_str = ", ".join(ports) if ports else "none"
    role      = "HOST" if device.get("is_host") else "device"
    known     = "yes" if device.get("is_known") else "no (still learning)"
    label     = device.get("notes") or "—  <i>(/label to set)</i>"

    return (
        f"🔎 <b>Device Info</b>\n\n"
        f"<b>Label</b>      {_esc(label) if device.get('notes') else label}\n"
        f"<b>Role</b>       {role}\n"
        f"<b>Name</b>       {_esc(name)}\n"
        f"<b>MAC</b>        <code>{_esc(device['mac'])}</code>\n"
        f"<b>Last IP</b>    <code>{_esc(last_ip)}</code>\n"
        f"<b>Vendor</b>     {_esc(device.get('vendor') or 'Unknown')}\n"
        f"<b>Hostname</b>   {_esc(device.get('hostname') or '—')}\n"
        f"<b>OS</b>         {_esc(os_disp)}\n"
        f"<b>Open ports</b> {_esc(ports_str)}\n"
        f"<b>First seen</b> {device['first_seen'][:19]}\n"
        f"<b>Last seen</b>  {device['last_seen'][:19]}\n"
        f"<b>Times seen</b> {device['times_seen']}\n"
        f"<b>Known</b>      {known}"
    )


def health_message(heartbeat_age: float, last_scan_at: str,
                   device_count: int) -> str:
    healthy = heartbeat_age < 180
    icon    = "✅" if healthy else "🔴"
    status  = "HEALTHY" if healthy else "STALLED"
    age_min = heartbeat_age / 60

    return (
        f"{icon} <b>Monitor Health: {status}</b>\n\n"
        f"<b>Last heartbeat</b>  {age_min:.1f} min ago\n"
        f"<b>Last scan</b>       {last_scan_at[:19] if last_scan_at else 'never'}\n"
        f"<b>Devices tracked</b> {device_count}"
        + ("\n\n⚠️ Restart: <code>docker compose restart</code>" if not healthy else "")
    )


def label_message(ip: str, label: str, device: dict) -> str:
    """Response after successfully setting or clearing a label."""
    mac    = device["mac"]
    vendor = device.get("vendor") or "Unknown"
    if label:
        return (
            f"🏷️ <b>Device Labelled</b>\n\n"
            f"<b>Label</b>  {_esc(label)}\n"
            f"<b>IP</b>     <code>{_esc(ip)}</code>\n"
            f"<b>MAC</b>    <code>{_esc(mac)}</code>\n"
            f"<b>Vendor</b> {_esc(vendor)}\n\n"
            f"<i>This name will appear in all future alerts.</i>"
        )
    else:
        return (
            f"🏷️ <b>Label Cleared</b>\n\n"
            f"<b>IP</b>     <code>{_esc(ip)}</code>\n"
            f"<b>MAC</b>    <code>{_esc(mac)}</code>\n\n"
            f"<i>Device will show vendor/hostname again.</i>"
        )


def help_message() -> str:
    return (
        "🤖 <b>Network Monitor Commands</b>\n\n"
        "/devices               — All devices with status\n"
        "/alerts                — Last 10 alerts\n"
        "/stats                 — Scan &amp; alert summary\n"
        "/ports &lt;ip&gt;          — Open ports for a device\n"
        "/whois &lt;ip&gt;          — Full device detail\n"
        "/label &lt;ip&gt; &lt;name&gt;  — Label a device\n"
        "/label &lt;ip&gt; -         — Clear a device label\n"
        "/scan                  — Trigger an immediate scan\n"
        "/health                — Monitor health &amp; heartbeat\n"
        "/help                  — This message"
    )


# ── Internal helpers ──────────────────────────────────────────────────────────

def _get_latest_scan_id() -> int | None:
    with db.get_conn() as conn:
        row = conn.execute(
            "SELECT id FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
    return row[0] if row else None


def _get_online_macs(scan_id: int | None) -> set[str]:
    if scan_id is None:
        return set()
    with db.get_conn() as conn:
        rows = conn.execute(
            "SELECT DISTINCT mac FROM scan_events WHERE scan_id=? AND status='online'",
            (scan_id,)
        ).fetchall()
    return {r[0] for r in rows}


def _get_last_ip(mac: str) -> str:
    with db.get_conn() as conn:
        row = conn.execute("""
            SELECT ip FROM scan_events
            WHERE mac=? AND status='online'
            ORDER BY scanned_at DESC LIMIT 1
        """, (mac,)).fetchone()
    return row[0] if row else "—"


def _get_last_ports(mac: str) -> list[str]:
    with db.get_conn() as conn:
        row = conn.execute("""
            SELECT open_ports FROM scan_events
            WHERE mac=? AND status='online'
            ORDER BY scanned_at DESC LIMIT 1
        """, (mac,)).fetchone()
    if row and row[0]:
        return row[0].split(",")
    return []


def _resolve_device(identifier: str) -> tuple[dict | None, str, list[str]]:
    """Find device by MAC or IP. Returns (device, last_ip, ports)."""
    identifier = identifier.strip()

    # Try MAC first
    device = db.get_device(identifier.upper())

    # Try IP lookup
    if not device:
        with db.get_conn() as conn:
            row = conn.execute("""
                SELECT mac FROM scan_events
                WHERE ip=? ORDER BY scanned_at DESC LIMIT 1
            """, (identifier,)).fetchone()
        if row:
            device = db.get_device(row[0])

    if not device:
        return None, "", []

    last_ip = _get_last_ip(device["mac"])
    ports   = _get_last_ports(device["mac"])
    return device, last_ip, ports


def alert_device_online(mac: str, ip: str, vendor: str,
                        hostname: str, ports: list[str],
                        label: str = "") -> str:
    name      = label or hostname or vendor or mac
    ports_str = ", ".join(ports) if ports else "none"
    return (
        f"✅ <b>Device Back Online</b>\n\n"
        f"<b>Name</b>   {_esc(name)}\n"
        f"<b>MAC</b>    <code>{_esc(mac)}</code>\n"
        f"<b>IP</b>     <code>{_esc(ip)}</code>\n"
        f"<b>Ports</b>  {_esc(ports_str)}"
    )


def alive_ping(next_ping_hours: int = 6) -> str:
    """
    Periodic proof-of-life message.
    If this stops arriving, the container is down — no watchdog needed.
    """
    with db.get_conn() as conn:
        total  = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        sid    = conn.execute(
            "SELECT id FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
        latest_sid = sid[0] if sid else 0
        online = conn.execute(
            "SELECT COUNT(DISTINCT mac) FROM scan_events "
            "WHERE scan_id=? AND status='online'", (latest_sid,)
        ).fetchone()[0]
        last_scan = conn.execute(
            "SELECT started_at FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()

    last_str = last_scan[0][:19] if last_scan else "never"
    return (
        f"✅ <b>Monitor Alive</b>\n\n"
        f"<b>Online</b>    : {online} / {total} devices\n"
        f"<b>Last scan</b> : {last_str}\n\n"
        f"<i>Next check-in in {next_ping_hours}h. "
        f"If this stops arriving, the agent is down.</i>"
    )


    """Full daily digest pushed at 06:00 EAT."""
    with db.get_conn() as conn:
        total_devices = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        known_devices = conn.execute(
            "SELECT COUNT(*) FROM devices WHERE is_known=1"
        ).fetchone()[0]

        # Online/offline from latest scan
        sid = conn.execute(
            "SELECT id FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
        latest_sid = sid[0] if sid else 0
        online_ct  = conn.execute(
            "SELECT COUNT(DISTINCT mac) FROM scan_events "
            "WHERE scan_id=? AND status='online'", (latest_sid,)
        ).fetchone()[0]
        offline_ct = total_devices - online_ct

        # Alerts in last 24h
        from monitor.timeutil import ago
        cutoff = ago(60 * 24)  # 24 hours
        alerts_24h  = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE created_at > ?", (cutoff,)
        ).fetchone()[0]
        new_dev_24h = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE alert_type='new_device' AND created_at > ?",
            (cutoff,)
        ).fetchone()[0]
        offline_24h = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE alert_type='device_offline' AND created_at > ?",
            (cutoff,)
        ).fetchone()[0]
        port_24h    = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE alert_type='new_port' AND created_at > ?",
            (cutoff,)
        ).fetchone()[0]

        # Scans in last 24h
        scans_24h = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE started_at > ?", (cutoff,)
        ).fetchone()[0]

    return (
        f"📋 <b>Daily Network Summary</b>\n\n"
        f"<b>Devices</b>\n"
        f"  Total    : {total_devices}  (known: {known_devices})\n"
        f"  Online   : {online_ct}\n"
        f"  Offline  : {offline_ct}\n\n"
        f"<b>Last 24 hours</b>\n"
        f"  Scans run      : {scans_24h}\n"
        f"  Total alerts   : {alerts_24h}\n"
        f"  New devices    : {new_dev_24h}\n"
        f"  Went offline   : {offline_24h}\n"
        f"  New ports      : {port_24h}"
    )
