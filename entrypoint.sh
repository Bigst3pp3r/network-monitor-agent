#!/bin/bash
# entrypoint.sh — Runs as root (required for nmap -O raw socket access).
# Privilege escalation is prevented by no-new-privileges in docker-compose.yml.

mkdir -p /app/data /app/logs /app/data/exports

exec python -m monitor.main
