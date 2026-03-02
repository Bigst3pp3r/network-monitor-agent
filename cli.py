#!/usr/bin/env python3
"""
cli.py — Query the monitor database from the host machine.

Usage:
    python3 cli.py devices
    python3 cli.py alerts
    python3 cli.py export
    python3 cli.py stats
    python3 cli.py health
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

DATA_PATH = os.getenv("DATA_PATH", os.path.join(os.path.dirname(__file__), "data"))

import monitor.config as cfg
cfg.DB_PATH        = os.path.join(DATA_PATH, "network.db")
cfg.LOG_PATH       = os.path.join(DATA_PATH, "cli.log")
cfg.DATA_DIR       = DATA_PATH
cfg.EXPORT_DIR     = os.path.join(DATA_PATH, "exports")
cfg.HEARTBEAT_PATH = os.path.join(DATA_PATH, "heartbeat")

from monitor import db
from monitor.reporter import print_device_table, print_recent_alerts, export_csv_snapshot


def cmd_devices():
    print_device_table()


def cmd_alerts():
    print_recent_alerts(limit=20)


def cmd_export():
    path = export_csv_snapshot()
    print(f"Exported to: {path}")


def cmd_stats():
    try:
        from rich.console import Console
        console = Console()

        with db.get_conn() as conn:
            total_devices  = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
            host_devices   = conn.execute("SELECT COUNT(*) FROM devices WHERE is_host=1").fetchone()[0]
            net_devices    = total_devices - host_devices
            known_devices  = conn.execute("SELECT COUNT(*) FROM devices WHERE is_known=1").fetchone()[0]

                    # CORRECT — count MACs present in the latest scan_id
            latest_scan = conn.execute(
                "SELECT id FROM scans ORDER BY id DESC LIMIT 1"
            ).fetchone()
            latest_scan_id = latest_scan[0] if latest_scan else 0

            online_count = conn.execute("""
                SELECT COUNT(DISTINCT mac) FROM scan_events
                WHERE scan_id = ? AND status = 'online'
            """, (latest_scan_id,)).fetchone()[0]

            offline_count = conn.execute("""
                SELECT COUNT(*) FROM devices
                WHERE mac NOT IN (
                    SELECT DISTINCT mac FROM scan_events
                    WHERE scan_id = ? AND status = 'online'
                )
            """, (latest_scan_id,)).fetchone()[0]

            total_scans    = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            total_alerts   = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            warn_alerts    = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='WARNING'").fetchone()[0]
            new_dev_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE alert_type='new_device'").fetchone()[0]
            offline_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE alert_type='device_offline'").fetchone()[0]
            port_alerts    = conn.execute("SELECT COUNT(*) FROM alerts WHERE alert_type='new_port'").fetchone()[0]
            last_scan      = conn.execute(
                "SELECT started_at, devices_found FROM scans ORDER BY id DESC LIMIT 1"
            ).fetchone()

        console.print()
        console.print("[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]")
        console.print("[bold cyan]  Network Monitor — Statistics         [/bold cyan]")
        console.print("[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]")
        console.print()
        console.print("[bold]Devices[/bold]")
        console.print(f"  This machine (host)  : [bold green]{host_devices}[/bold green]")
        console.print(f"  Network devices      : [green]{net_devices}[/green]")
        console.print(f"  Known (baselined)    : [green]{known_devices}[/green]")
        console.print(f"  Currently online     : [bold green]{online_count}[/bold green]")
        console.print(f"  Currently offline    : [red]{offline_count}[/red]")
        console.print()
        console.print("[bold]Scanning[/bold]")
        console.print(f"  Total scans run      : [blue]{total_scans}[/blue]")
        if last_scan:
            console.print(f"  Last scan at         : [dim]{last_scan[0][:19]}[/dim]")
            console.print(f"  Devices in last scan : [dim]{last_scan[1]}[/dim]")
        console.print()
        console.print("[bold]Alerts[/bold]")
        console.print(f"  Total alerts         : [yellow]{total_alerts}[/yellow]")
        console.print(f"  Warnings             : [yellow]{warn_alerts}[/yellow]")
        console.print(f"  New device           : [yellow]{new_dev_alerts}[/yellow]")
        console.print(f"  Device offline       : [dim]{offline_alerts}[/dim]")
        console.print(f"  New port opened      : [yellow]{port_alerts}[/yellow]")
        console.print()

    except Exception as e:
        print(f"Error: {e}")
        import traceback; traceback.print_exc()


def cmd_health():
    import time
    try:
        from rich.console import Console
        console = Console()
    except ImportError:
        console = None

    hb_path = cfg.HEARTBEAT_PATH
    if not os.path.exists(hb_path):
        print("UNKNOWN — heartbeat file not found (no scan has run yet)")
        return

    age_secs = time.time() - os.path.getmtime(hb_path)
    age_mins = age_secs / 60
    with open(hb_path) as f:
        last_beat = f.read().strip()

    healthy = age_secs < 180
    if console:
        status = "[bold green]HEALTHY[/bold green]" if healthy else "[bold red]STALLED[/bold red]"
        console.print(f"\nScan loop : {status}")
        console.print(f"  Last beat : {last_beat} ({age_mins:.1f} min ago)")
        if not healthy:
            console.print("  [red]→ Restart container: docker compose restart[/red]")
        console.print()
    else:
        print(f"{'HEALTHY' if healthy else 'STALLED'} — {last_beat} ({age_mins:.1f} min ago)")


COMMANDS = {
    "devices": cmd_devices,
    "alerts":  cmd_alerts,
    "export":  cmd_export,
    "stats":   cmd_stats,
    "health":  cmd_health,
}


def usage():
    print("Usage: python3 cli.py [devices|alerts|export|stats|health]")
    sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        usage()
    COMMANDS[sys.argv[1]]()
