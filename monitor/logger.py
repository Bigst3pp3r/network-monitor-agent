"""
logger.py — Configures logging to both console (with colour via rich)
and a rotating file in /app/logs/monitor.log.
"""

import logging
import logging.handlers
import os
from monitor.config import LOG_PATH, LOG_LEVEL, LOG_DIR


def setup_logging():
    os.makedirs(LOG_DIR, exist_ok=True)

    level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)

    # Root logger
    root = logging.getLogger()
    root.setLevel(level)

    # ── Console handler (rich if available) ──────────────────────────────────
    try:
        from rich.logging import RichHandler
        console_handler = RichHandler(
            rich_tracebacks=True,
            show_path=False,
            markup=True
        )
        console_handler.setLevel(level)
        console_fmt = logging.Formatter("%(message)s", datefmt="[%X]")
        console_handler.setFormatter(console_fmt)
    except ImportError:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
        )
        console_handler.setFormatter(console_fmt)

    # ── File handler (rotating, max 5 MB × 3 files) ───────────────────────────
    file_handler = logging.handlers.RotatingFileHandler(
        LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setLevel(level)
    file_fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(file_fmt)

    root.addHandler(console_handler)
    root.addHandler(file_handler)

    # Silence noisy third-party loggers
    for noisy in ("scapy.runtime", "urllib3", "requests"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
