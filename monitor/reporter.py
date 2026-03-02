"""
reporter.py — Console output and CSV export.

Status logic
------------
A device is ONLINE only if it appeared in the MOST RECENT scan cycle
(matched by the latest scan_id). This prevents stale "online" badges
for devices that went offline but whose old scan_event still says online.
"""

import os
import logging
from monitor.timeutil import now_display, now_file
from monitor import db
from monitor.config import EXPORT_DIR

log = logging.getLogger(__name__)


def _get_latest_scan_id() -> int | None:
    with db.get_conn() as conn:
        row = conn.execute(
            "SELECT id FROM scans ORDER BY id DESC LIMIT 1"
        ).fetchone()
    return row["id"] if row else None


def _build_status_map(latest_scan_id: int | None) -> dict[str, str]:
    """
    Returns {mac: 'online'} for every device present in the latest scan.
    Any MAC NOT in this dict is offline (or never scanned).
    """
    if latest_scan_id is None:
        return {}
    with db.get_conn() as conn:
        rows = conn.execute("""
            SELECT DISTINCT mac FROM scan_events
            WHERE scan_id = ? AND status = 'online'
        """, (latest_scan_id,)).fetchall()
    return {row["mac"]: "online" for row in rows}


def print_scan_summary(scan_result: dict, total_online: int):
    try:
        from rich.console import Console
        console = Console()
        console.print()
        console.print(f"[bold cyan]═══ Scan Complete  [{now_display()}] ═══[/bold cyan]")
        console.print(f"  [green]Devices online   :[/green] {total_online}")
        console.print(f"  [yellow]New devices      :[/yellow] {scan_result['new_devices']}")
        console.print(f"  [red]Devices offline  :[/red] {scan_result['offline_devices']}")
        console.print(f"  [magenta]Alerts raised    :[/magenta] {scan_result['alerts_raised']}")
        console.print()
    except ImportError:
        log.info("Scan done | online=%d new=%d offline=%d alerts=%d",
                 total_online, scan_result["new_devices"],
                 scan_result["offline_devices"], scan_result["alerts_raised"])


def print_device_table():
    try:
        from rich.console import Console
        from rich.table import Table
        from rich import box

        console = Console()
        devices        = db.get_all_devices()
        latest_scan_id = _get_latest_scan_id()
        status_map     = _build_status_map(latest_scan_id)

        table = Table(title="Network Device Inventory", box=box.ROUNDED, show_lines=True)
        table.add_column("Role",        style="bold",  no_wrap=True, width=8)
        table.add_column("Status",      no_wrap=True,  width=10)
        table.add_column("MAC Address", style="cyan",  no_wrap=True)
        table.add_column("Last IP",     style="green", no_wrap=True)
        table.add_column("Vendor",      style="yellow")
        table.add_column("Hostname",    style="white")
        table.add_column("OS",          style="blue")
        table.add_column("Open Ports",  style="magenta")
        table.add_column("Last Seen",   style="dim",   no_wrap=True)
        table.add_column("Known",       justify="center")

        for d in devices:
            with db.get_conn() as conn:
                row = conn.execute("""
                    SELECT ip, open_ports FROM scan_events
                    WHERE mac = ? AND status = 'online'
                    ORDER BY scanned_at DESC LIMIT 1
                """, (d["mac"],)).fetchone()

            last_ip       = row["ip"]         if row else "—"
            open_ports    = row["open_ports"] if (row and row["open_ports"]) else ""
            ports_display = "\n".join(open_ports.split(",")) if open_ports \
                            else "[dim]none[/dim]"

            os_raw = d.get("os_info") or ""
            os_acc = d.get("os_accuracy") or 0
            os_display = (os_raw if os_acc >= 100 else f"{os_raw}\n[dim]({os_acc}%)[/dim]") \
                         if os_raw else "[dim]unknown[/dim]"

            role = "[bold green]HOST[/bold green]" if d.get("is_host") \
                   else "[dim]device[/dim]"

            # KEY FIX: status from latest scan_id, not latest scan_event row
            is_online    = status_map.get(d["mac"]) == "online"
            status_badge = "[bold green]● online[/bold green]" if is_online \
                           else "[red]○ offline[/red]"

            table.add_row(
                role, status_badge, d["mac"], last_ip,
                d.get("vendor") or "Unknown",
                d.get("hostname") or "—",
                os_display, ports_display,
                d["last_seen"][:19],
                "✓" if d["is_known"] else "·",
            )

        console.print(table)

    except ImportError:
        latest_scan_id = _get_latest_scan_id()
        status_map     = _build_status_map(latest_scan_id)
        for d in db.get_all_devices():
            with db.get_conn() as conn:
                row = conn.execute("""
                    SELECT ip, open_ports FROM scan_events
                    WHERE mac = ? AND status = 'online'
                    ORDER BY scanned_at DESC LIMIT 1
                """, (d["mac"],)).fetchone()
            role   = "[HOST]" if d.get("is_host") else "[device]"
            status = "online" if status_map.get(d["mac"]) == "online" else "offline"
            ports  = row["open_ports"] if (row and row["open_ports"]) else "none"
            log.info("%s [%s] %s  %s  ports=%s", role, status, d["mac"],
                     d.get("vendor","?"), ports)


def print_recent_alerts(limit: int = 10):
    try:
        from rich.console import Console
        from rich.table import Table
        from rich import box
        console = Console()
        alerts  = db.get_recent_alerts(limit)
        if not alerts:
            console.print("[dim]No alerts recorded yet.[/dim]")
            return
        table = Table(title=f"Last {limit} Alerts", box=box.SIMPLE_HEAVY)
        table.add_column("Time",     style="dim",    no_wrap=True)
        table.add_column("Type",     style="yellow", no_wrap=True)
        table.add_column("Severity", justify="center")
        table.add_column("MAC",      style="cyan")
        table.add_column("Detail",   style="white")
        severity_color = {"INFO": "blue", "WARNING": "yellow", "CRITICAL": "red"}
        for a in alerts:
            sev = a["severity"]
            table.add_row(
                a["created_at"][:19], a["alert_type"],
                f"[{severity_color.get(sev,'white')}]{sev}[/{severity_color.get(sev,'white')}]",
                a.get("mac") or "—",
                a["detail"][:80] + ("…" if len(a["detail"]) > 80 else ""),
            )
        console.print(table)
    except ImportError:
        for a in db.get_recent_alerts(limit):
            log.info("[%s] %s — %s", a["severity"], a["alert_type"], a["detail"])


def export_csv_snapshot():
    os.makedirs(EXPORT_DIR, exist_ok=True)
    path = os.path.join(EXPORT_DIR, f"devices_{now_file()}.csv")
    db.export_devices_csv(path)
    log.info("CSV snapshot written to %s", path)
    return path