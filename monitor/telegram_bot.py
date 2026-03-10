"""
telegram_bot.py — Telegram bot client.

Architecture
------------
The bot runs in a dedicated background thread with its own asyncio event loop.
The main scan loop (synchronous) calls send_alert() / send_message() which
use asyncio.run_coroutine_threadsafe() to safely cross the sync/async boundary.

Security
--------
TELEGRAM_CHAT_ID whitelist: the bot silently ignores every message from any
chat_id that isn't in the whitelist. This means even if someone finds your
bot token they cannot query your network data.

Flood guard
-----------
A sliding window counter prevents more than ALERT_FLOOD_LIMIT alerts per
60 seconds. Excess alerts are dropped (not queued) to avoid delayed spam
storms during network events.
"""

import asyncio
import logging
import threading
import time
from collections import deque

from monitor.config import (
    TELEGRAM_TOKEN, TELEGRAM_CHAT_ID,
    ALERT_FLOOD_LIMIT, NETWORK_SUBNET, SCAN_INTERVAL,
)

log = logging.getLogger(__name__)

# Module-level singleton — set by TelegramBot.start()
_bot_instance: "TelegramBot | None" = None


def get_bot() -> "TelegramBot | None":
    return _bot_instance


class TelegramBot:
    """
    Wraps python-telegram-bot Application in a background thread.
    All public methods are safe to call from synchronous code.
    """

    def __init__(self):
        self._app        = None
        self._loop       = None
        self._thread     = None
        self._ready      = threading.Event()
        self._stopping   = False

        # Flood guard: sliding window of send timestamps
        self._send_times: deque = deque()
        self._flood_lock = threading.Lock()

    # ── Public sync API ───────────────────────────────────────────────────────

    def start(self):
        """Start the bot in a background thread. Blocks until ready."""
        if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
            log.warning("Telegram not configured — bot disabled "
                        "(set TELEGRAM_TOKEN and TELEGRAM_CHAT_ID in .env)")
            return

        self._thread = threading.Thread(
            target=self._run_loop,
            name="telegram-bot",
            daemon=True,
        )
        self._thread.start()

        if self._ready.wait(timeout=30):
            log.info("Telegram bot ready")
        else:
            log.warning("Telegram bot did not become ready within 30s")

    def stop(self, message: str | None = None):
        """Send shutdown message and stop the bot cleanly."""
        if not self._loop or not self._app:
            return
        self._stopping = True
        if message:
            self.send_message(message)
        future = asyncio.run_coroutine_threadsafe(
            self._shutdown_async(), self._loop
        )
        try:
            future.result(timeout=15)
        except Exception as e:
            log.debug("Bot shutdown error: %s", e)

    def send_message(self, text: str, parse_mode: str = "HTML") -> bool:
        """
        Send a message to the configured chat.
        Returns True if sent, False if bot not ready or send failed.
        """
        if not self._loop or not self._app or self._stopping:
            return False

        future = asyncio.run_coroutine_threadsafe(
            self._send_async(text, parse_mode), self._loop
        )
        try:
            return future.result(timeout=10)
        except Exception as e:
            log.warning("Telegram send failed: %s", e)
            return False

    def send_alert(self, text: str) -> bool:
        """
        Send an alert message — subject to flood guard.
        Drops the message (returns False) if rate limit exceeded.
        """
        if not self._is_flood_allowed():
            log.warning("Telegram flood guard: alert dropped")
            return False
        return self.send_message(text)

    # ── Flood guard ───────────────────────────────────────────────────────────

    def _is_flood_allowed(self) -> bool:
        """
        Sliding window rate limiter.
        Returns True if sending is allowed, False if rate limit exceeded.
        """
        now = time.monotonic()
        with self._flood_lock:
            # Drop timestamps older than 60 seconds
            while self._send_times and now - self._send_times[0] > 60:
                self._send_times.popleft()

            if len(self._send_times) >= ALERT_FLOOD_LIMIT:
                return False

            self._send_times.append(now)
            return True

    # ── Async internals ───────────────────────────────────────────────────────

    def _run_loop(self):
        """Entry point for the background thread — owns its own event loop."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._start_async())
        except Exception as e:
            log.error("Telegram bot loop error: %s", e)
        finally:
            self._loop.close()

    async def _start_async(self):
        from telegram.ext import Application, CommandHandler, MessageHandler, filters
        from monitor.commands import (
            cmd_start, cmd_help, cmd_devices, cmd_alerts,
            cmd_stats, cmd_ports, cmd_whois, cmd_scan,
            cmd_health, cmd_label, unknown_command,
        )

        self._app = (
            Application.builder()
            .token(TELEGRAM_TOKEN)
            .build()
        )

        # Register command handlers
        handlers = [
            ("start",   cmd_start),
            ("help",    cmd_help),
            ("devices", cmd_devices),
            ("alerts",  cmd_alerts),
            ("stats",   cmd_stats),
            ("ports",   cmd_ports),
            ("whois",   cmd_whois),
            ("scan",    cmd_scan),
            ("health",  cmd_health),
            ("label",   cmd_label),
        ]
        for name, handler in handlers:
            self._app.add_handler(CommandHandler(name, handler))

        # Catch unknown commands
        self._app.add_handler(
            MessageHandler(filters.COMMAND, unknown_command)
        )

        await self._app.initialize()
        await self._app.start()
        await self._app.updater.start_polling(drop_pending_updates=True)

        self._ready.set()
        log.info("Telegram bot polling started")

        # Keep the coroutine alive until stop() is called
        while not self._stopping:
            await asyncio.sleep(1)

    async def _send_async(self, text: str, parse_mode: str) -> bool:
        try:
            await self._app.bot.send_message(
                chat_id=TELEGRAM_CHAT_ID,
                text=text,
                parse_mode=parse_mode,
            )
            return True
        except Exception as e:
            log.warning("Telegram send error: %s", e)
            return False

    async def _shutdown_async(self):
        try:
            await self._app.updater.stop()
            await self._app.stop()
            await self._app.shutdown()
        except Exception as e:
            log.debug("Shutdown sequence error: %s", e)


# ── Auth guard decorator ──────────────────────────────────────────────────────

def authorised(handler):
    """
    Decorator for command handlers.
    Silently ignores any message not from TELEGRAM_CHAT_ID.
    """
    async def wrapper(update, context):
        if str(update.effective_chat.id) != str(TELEGRAM_CHAT_ID):
            log.warning("Unauthorised Telegram access from chat_id=%s",
                        update.effective_chat.id)
            return  # silent drop — don't reveal the bot exists
        return await handler(update, context)
    wrapper.__name__ = handler.__name__
    return wrapper
