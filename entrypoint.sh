#!/bin/bash
# entrypoint.sh — Fix volume mount permissions then run as scanner user

# Ensure the scanner user owns the mounted data/logs directories
# (Docker creates mounted volumes as root, so we fix this at startup)
chown -R scanner:scanner /app/data /app/logs 2>/dev/null || true

# Drop privileges and run the monitor
exec gosu scanner python -m monitor.main
