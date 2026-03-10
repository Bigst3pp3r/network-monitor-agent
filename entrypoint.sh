#!/bin/bash
# entrypoint.sh — Runs as root (required for nmap -O raw socket access).
# Privilege escalation is prevented by no-new-privileges in docker-compose.yml.
#
# Permissions strategy:
# - data/ and logs/ are 755 so the host user can run cli.py directly
# - Sensitive files (.env, heartbeat) stay 600 — set explicitly below
# - WAL sidecar files (-wal, -shm) need to be group/world readable
#   for SQLite WAL mode to work correctly from multiple processes

set -e

mkdir -p /app/data /app/logs /app/data/exports

# Directories: owner rwx, group r-x, other r-x
# Allows host user to cd into data/ and read files
chmod 755 /app/data /app/logs /app/data/exports

# DB and exports: readable by host user for cli.py
# WAL mode requires that readers can also write the -shm file,
# so we need group/other write on the DB and its sidecars
chmod 644 /app/data/network.db      2>/dev/null || true
chmod 644 /app/data/network.db-wal  2>/dev/null || true
chmod 644 /app/data/network.db-shm  2>/dev/null || true

# Non-sensitive data files: world-readable
find /app/data/exports -type f -exec chmod 644 {} \; 2>/dev/null || true
chmod 644 /app/data/oui.db          2>/dev/null || true
chmod 644 /app/data/oui_api_cache.json 2>/dev/null || true

# Heartbeat: readable so host watchdog scripts can check mtime
chmod 644 /app/data/heartbeat       2>/dev/null || true

# Logs: readable for debugging from host
find /app/logs -type f -exec chmod 644 {} \; 2>/dev/null || true

exec python -m monitor.main
