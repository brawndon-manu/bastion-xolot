"""
Bastión Xólot — Enforcement Audit Module (Phase 4 — STUB)

STATUS: Not yet implemented. Scheduled for Phase 4 (Mar 2 – Mar 8).

This module maintains a local audit trail of all enforcement actions
(quarantines, blocks, rollbacks) performed by the system.  The audit
log is required by the project proposal for accountability and
one-tap rollback support.

Audit record fields (per enforcement.schema.json):
  - action taken
  - affected device or destination
  - timestamp
  - reason for enforcement
  - whether initiated automatically or by user
  - current status (applied / rolled_back / failed)

Storage:
  - Local SQLite table (agent-side)
  - Synced to backend via enforcement events
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def log_enforcement_action(
    device_id: str,
    action: str,
    reason: str,
    initiated_by: str = "system",
    alert_id: str | None = None,
) -> str | None:
    """
    Record an enforcement action in the local audit log.

    Phase 4 implementation will:
      1. Create audit record in local SQLite
      2. Build enforcement_action event
      3. Dispatch to backend for persistence

    Returns the audit record ID, or None if logging failed.
    """
    logger.debug(
        "audit.log_enforcement_action(%s, %s) — not yet implemented (Phase 4)",
        device_id, action,
    )
    return None


def get_audit_history(device_id: str | None = None, limit: int = 50) -> list[dict]:
    """
    Retrieve enforcement audit history.

    If device_id is specified, returns only actions for that device.
    Otherwise returns all recent actions.
    """
    logger.debug("audit.get_audit_history() — not yet implemented (Phase 4)")
    return []
