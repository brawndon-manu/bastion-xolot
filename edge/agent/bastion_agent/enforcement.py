"""
Bastión Xólot — Enforcement Module (Phase 4 — STUB)

STATUS: Not yet implemented. Scheduled for Phase 4 (Mar 2 – Mar 8).

This module provides the detection-side interface for enforcement
actions.  The actual firewall / DNS rule changes are owned by the
Systems Architect; this module:

  1. Tags alerts with recommended enforcement actions
  2. Provides evidence context for enforcement decisions
  3. Validates that enforcement is safe before requesting it

Enforcement types:
  - quarantine:          Isolate a device (block all outbound except admin)
  - unquarantine:        Restore normal access
  - block_destination:   Block a specific domain or IP via DNS/firewall
  - unblock_destination: Reverse a destination block
  - monitor_only:        Flag for observation without blocking

Safety rules:
  - All actions are reversible
  - MONITOR_ONLY mode prevents any enforcement
  - DRY_RUN logs actions without executing
  - ALLOW_ENFORCEMENT must be explicitly True
  - config.enforcement_allowed() must return True

NOTE: The actual iptables/nftables/dnsmasq commands are implemented
      by the Systems Architect.  This module only recommends and
      validates actions.
"""

import logging
from bastion_agent.config import enforcement_allowed, DRY_RUN

logger = logging.getLogger(__name__)


def recommend_action(alert: dict) -> str | None:
    """
    Given an alert, recommend an enforcement action.

    Phase 4 implementation will analyze alert severity, type,
    and evidence to suggest the appropriate response.

    Returns action string or None if no action recommended.
    """
    logger.debug("enforcement.recommend_action() — not yet implemented (Phase 4)")
    return None


def request_quarantine(device_mac: str, reason: str) -> bool:
    """
    Request quarantine of a device.

    Phase 4 implementation will:
      1. Check enforcement_allowed()
      2. Validate the device exists
      3. Call the Systems Architect's quarantine script/API
      4. Log the action in audit history

    Returns True if quarantine was applied, False otherwise.
    """
    if not enforcement_allowed():
        logger.info("Quarantine requested for %s but enforcement is not allowed", device_mac)
        return False

    if DRY_RUN:
        logger.info("[DRY RUN] Would quarantine device: %s — reason: %s", device_mac, reason)
        return False

    logger.debug("enforcement.request_quarantine(%s) — not yet implemented (Phase 4)", device_mac)
    return False


def request_unquarantine(device_mac: str, reason: str) -> bool:
    """
    Request removal of quarantine for a device.

    Returns True if unquarantine was applied, False otherwise.
    """
    if not enforcement_allowed():
        logger.info("Unquarantine requested for %s but enforcement is not allowed", device_mac)
        return False

    logger.debug(
        "enforcement.request_unquarantine(%s) — not yet implemented (Phase 4)", device_mac
    )
    return False
