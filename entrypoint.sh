#!/bin/bash
# entrypoint.sh — Runs as root (required for nmap -O raw socket access).
# Privilege escalation is prevented by no-new-privileges in docker-compose.yml.

set -e

mkdir -p /app/data /app/logs /app/data/exports

# Lock down data directory:
# - Root owns everything
# - Owner: read+write, Group: none, Other: none (700 for dirs, 600 for files)
# This means only root inside the container (and root on the host) can read
# the network.db, logs, and future Telegram token — not other host users.
chmod 700 /app/data /app/logs /app/data/exports
find /app/data -type f -exec chmod 600 {} \; 2>/dev/null || true
find /app/logs -type f -exec chmod 600 {} \; 2>/dev/null || true

exec python -m monitor.main
