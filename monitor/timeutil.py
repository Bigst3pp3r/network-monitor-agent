"""
timeutil.py — Centralised timezone-aware datetime helpers.

All timestamps in the system use East Africa Time (UTC+3, Africa/Nairobi).
Import `now()` wherever a timestamp is needed — never call utcnow() directly.
"""

from datetime import datetime, timezone, timedelta

# East Africa Time: UTC+3, no DST
EAT = timezone(timedelta(hours=3), name="EAT")


def now() -> datetime:
    """Return current time as a timezone-aware EAT datetime."""
    return datetime.now(EAT)


def now_iso() -> str:
    """Return current EAT time as an ISO 8601 string."""
    return now().isoformat()


def now_display() -> str:
    """Human-readable EAT timestamp for console output."""
    return now().strftime("%Y-%m-%d %H:%M:%S EAT")


def now_file() -> str:
    """Compact EAT timestamp safe for use in filenames."""
    return now().strftime("%Y%m%d_%H%M%S")


def ago(minutes: int) -> str:
    """Return ISO string for N minutes ago in EAT — used for dedup window."""
    return (now() - timedelta(minutes=minutes)).isoformat()
