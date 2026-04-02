from __future__ import annotations

from typing import Dict, Any
from bastion_agent import enforcement
from bastion_agent.config import PROTECTED_MACS


def handle_event(event: Dict[str, Any]) -> dict:
    if mac and mac.lower() in PROTECTED_MACS:
        return {
            "result": {
            "status": "IGNORED",
            "reason": "protected device"
        }
    }
    """
    Entry point for detection events.

    This function:
    - Receives normalized event input
    - Applies simple policy logic
    - Delegates enforcement decisions

    DOES NOT:
    - Touch nft directly
    - Modify system state directly
    """

    mac = event.get("mac")
    severity = event.get("severity", "low")
    reason = event.get("reason", "unknown")

    if not mac:
        raise ValueError("event missing mac")

    # POLICY ENGINE (Phase 5 R2)
    if severity == "high":
        return enforcement.request_quarantine_hard(
            mac=mac,
            reason=reason,
            actor="detection"
        )

    elif severity == "medium":
        return {
            "result": {
            "status": "IGNORED",
            "reason": "medium severity (monitor only)"
        }
    }
    # LOW severity -> ignore
    return {
        "result": {
            "status": "IGNORED",
            "reason": "low severity"
        }
    }