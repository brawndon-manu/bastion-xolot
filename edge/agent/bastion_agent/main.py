"""
Bastión Xólot — Edge Agent Main Loop

Entry point for the detection agent running on the Raspberry Pi gateway.
Orchestrates all detection modules on a periodic schedule:

  1. Device discovery — scans ARP table every DISCOVERY_INTERVAL seconds
  2. DNS monitoring  — polls dnsmasq logs every DNS_POLL_INTERVAL seconds
  3. Event dispatch  — sends queued events to backend API

Future phases will add:
  - Flow summary collection (Phase 3)
  - Baseline updates + anomaly checks (Phase 3)
  - Enforcement recommendations (Phase 4)

Usage:
  python -m bastion_agent.main          # direct execution
  bastion-agent                         # via pyproject.toml entry point

The agent runs as a systemd service in production:
  see infra/systemd/bastion-agent.service (owned by Systems Architect)
"""

import asyncio
import signal
import logging
import sys

from bastion_agent import __version__
from bastion_agent.config import (
    DISCOVERY_INTERVAL,
    DNS_POLL_INTERVAL,
    LOG_LEVEL,
    LOG_PATH,
    LOCAL_DB_PATH,
    BACKEND_URL,
    LAN_IFACE,
    MONITOR_ONLY,
    DRY_RUN,
)
from bastion_agent.storage import init_local_db, get_pending_events, mark_events_dispatched
from bastion_agent.discovery import scan_network
from bastion_agent.dns_monitor import DnsMonitor
from bastion_agent.events import dispatch_to_backend

logger = logging.getLogger("bastion_agent")

# ── Graceful shutdown flag ──
_shutdown = asyncio.Event()


def _setup_logging() -> None:
    """Configure logging for the agent process."""
    level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]

    # Also log to file if path is set and writable
    try:
        file_handler = logging.FileHandler(LOG_PATH)
        handlers.append(file_handler)
    except (OSError, IOError):
        pass  # file logging optional — stdout always works

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
    )


def _print_banner() -> None:
    """Log startup configuration for debugging."""
    logger.info("═══════════════════════════════════════════")
    logger.info("  Bastión Xólot Detection Agent v%s", __version__)
    logger.info("═══════════════════════════════════════════")
    logger.info("  LAN interface:       %s", LAN_IFACE)
    logger.info("  Backend URL:         %s", BACKEND_URL)
    logger.info("  Local DB:            %s", LOCAL_DB_PATH)
    logger.info("  Discovery interval:  %ds", DISCOVERY_INTERVAL)
    logger.info("  DNS poll interval:   %ds", DNS_POLL_INTERVAL)
    logger.info("  Monitor-only mode:   %s", MONITOR_ONLY)
    logger.info("  Dry-run mode:        %s", DRY_RUN)
    logger.info("═══════════════════════════════════════════")


# ─────────────────────────────────────────────
# Async task loops
# ─────────────────────────────────────────────

async def discovery_loop() -> None:
    """Periodically scan the neighbor table for devices."""
    logger.info("Discovery loop started (every %ds)", DISCOVERY_INTERVAL)

    while not _shutdown.is_set():
        try:
            events = scan_network()
            if events:
                logger.info("Discovery produced %d events", len(events))
        except Exception:
            logger.exception("Error in discovery loop")

        # Wait for interval or shutdown signal
        try:
            await asyncio.wait_for(_shutdown.wait(), timeout=DISCOVERY_INTERVAL)
            break  # shutdown requested
        except asyncio.TimeoutError:
            pass  # normal — interval elapsed, loop again


async def dns_monitor_loop() -> None:
    """Periodically poll DNS logs for blocked queries."""
    monitor = DnsMonitor()
    logger.info("DNS monitor loop started (every %ds)", DNS_POLL_INTERVAL)

    while not _shutdown.is_set():
        try:
            events = monitor.poll()
            if events:
                logger.info("DNS monitor produced %d events", len(events))
        except Exception:
            logger.exception("Error in DNS monitor loop")

        try:
            await asyncio.wait_for(_shutdown.wait(), timeout=DNS_POLL_INTERVAL)
            break
        except asyncio.TimeoutError:
            pass


async def dispatch_loop() -> None:
    """
    Periodically dispatch queued events to the backend API.

    Events are queued locally (storage.py) even when the backend is
    unreachable, and retried on the next cycle.

    NOTE: The POST /events endpoint is owned by the Backend Engineer.
    """
    dispatch_interval = max(DISCOVERY_INTERVAL, DNS_POLL_INTERVAL) + 5
    logger.info("Dispatch loop started (every %ds)", dispatch_interval)

    while not _shutdown.is_set():
        try:
            pending = get_pending_events(limit=50)
            if pending:
                dispatched = await dispatch_to_backend(pending)
                if dispatched:
                    mark_events_dispatched(dispatched)
                    logger.info(
                        "Dispatched %d/%d events to backend",
                        len(dispatched), len(pending),
                    )
        except Exception:
            logger.exception("Error in dispatch loop")

        try:
            await asyncio.wait_for(_shutdown.wait(), timeout=dispatch_interval)
            break
        except asyncio.TimeoutError:
            pass


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

async def _run() -> None:
    """Start all detection loops and wait for shutdown."""

    # Initialize local database
    init_local_db()

    _print_banner()

    # Launch all detection loops concurrently
    tasks = [
        asyncio.create_task(discovery_loop(), name="discovery"),
        asyncio.create_task(dns_monitor_loop(), name="dns_monitor"),
        asyncio.create_task(dispatch_loop(), name="dispatch"),
    ]

    # Wait for all tasks (they run until _shutdown is set)
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        logger.info("Agent tasks cancelled")


def _handle_signal(sig: signal.Signals) -> None:
    """Handle SIGINT/SIGTERM for graceful shutdown."""
    logger.info("Received %s — shutting down gracefully…", sig.name)
    _shutdown.set()


def main() -> None:
    """
    Main entry point — called by `bastion-agent` CLI command
    or `python -m bastion_agent.main`.
    """
    _setup_logging()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Register signal handlers for graceful shutdown
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_signal, sig)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            signal.signal(sig, lambda s, f: _handle_signal(signal.Signals(s)))

    try:
        loop.run_until_complete(_run())
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt — shutting down")
        _shutdown.set()
    finally:
        loop.close()
        logger.info("Bastión Xólot agent stopped")


if __name__ == "__main__":
    main()
