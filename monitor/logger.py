"""
logger.py — Configures logging to both console (with colour via rich)
and a rotating file in /app/logs/monitor.log.

Security: A SensitiveFilter scrubs the Telegram token and chat_id from
every log record before it is written anywhere. httpx / telegram library
loggers are silenced to WARNING to prevent token leaking via request URLs.
"""

import logging
import logging.handlers
import os
import re
from monitor.config import LOG_PATH, LOG_LEVEL, LOG_DIR


# ── Sensitive data filter ─────────────────────────────────────────────────────

class SensitiveFilter(logging.Filter):
    """
    Scrubs known sensitive values from log records in-place.

    Covers:
    - Telegram bot token  (40-char alphanumeric after 'bot')
    - Telegram chat ID    (numeric, positive or negative)
    - Raw token value     (if it somehow appears without the 'bot' prefix)

    Replacement is done on the final formatted message string so it catches
    values embedded in exception repr(), URL strings, and f-strings alike.
    """

    # Pattern: bot token as it appears in Telegram API URLs
    _TOKEN_IN_URL  = re.compile(r'bot\d{8,12}:[A-Za-z0-9_-]{35,}')
    # Pattern: raw token value (digits:base64url, no 'bot' prefix)
    _TOKEN_RAW     = re.compile(r'\d{8,12}:[A-Za-z0-9_-]{35,}')

    def __init__(self):
        super().__init__()
        self._token   = ""
        self._chat_id = ""
        # Compiled per-value patterns, rebuilt if config changes
        self._chat_re = None

    def configure(self, token: str, chat_id: str):
        """Call once after config is loaded to register sensitive values."""
        self._token   = token   or ""
        self._chat_id = str(chat_id).strip() if chat_id else ""
        if self._chat_id:
            escaped = re.escape(self._chat_id)
            self._chat_re = re.compile(escaped)

    def _scrub(self, text: str) -> str:
        # Scrub token-in-URL first (most specific)
        text = self._TOKEN_IN_URL.sub("bot[REDACTED]", text)
        # Scrub raw token value
        text = self._TOKEN_RAW.sub("[TOKEN REDACTED]", text)
        # Scrub literal chat_id if present
        if self._chat_re and self._chat_id:
            text = self._chat_re.sub("[CHAT_ID]", text)
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        # Scrub the pre-formatted message
        record.msg = self._scrub(str(record.msg))
        # Scrub any string args (these get interpolated into msg at emit time)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: self._scrub(str(v)) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            else:
                record.args = tuple(
                    self._scrub(str(a)) if isinstance(a, str) else a
                    for a in record.args
                )
        # Scrub exception text if present
        if record.exc_text:
            record.exc_text = self._scrub(record.exc_text)
        return True  # always emit — we scrub, not suppress


# Module-level filter instance so telegram_bot.py can call .configure()
sensitive_filter = SensitiveFilter()


def setup_logging():
    os.makedirs(LOG_DIR, exist_ok=True)

    level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)

    # Root logger
    root = logging.getLogger()
    root.setLevel(level)

    # ── Console handler (rich if available) ───────────────────────────────────
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

    # Attach scrubbing filter to each HANDLER, not the root logger.
    # Python propagates child logger records directly to parent handlers,
    # bypassing the parent logger's own filter() call. Adding to handlers
    # guarantees every record is scrubbed regardless of which logger emits it.
    console_handler.addFilter(sensitive_filter)
    file_handler.addFilter(sensitive_filter)

    # ── Silence noisy / token-leaking third-party loggers ─────────────────────
    # httpx logs full request URLs at DEBUG — these contain the bot token:
    #   GET https://api.telegram.org/bot<TOKEN>/getUpdates
    # Setting WARNING suppresses DEBUG and INFO traffic logs entirely.
    _silence = (
        "httpx",        # Telegram HTTP client — logs full URLs with token
        "httpcore",     # httpx transport layer
        "hpack",        # HTTP/2 header compression (chatty)
        "telegram",     # python-telegram-bot internals
        "telegram.ext", # dispatcher / updater logs
        "urllib3",      # legacy HTTP
        "requests",     # legacy HTTP
    )
    for name in _silence:
        logging.getLogger(name).setLevel(logging.WARNING)
