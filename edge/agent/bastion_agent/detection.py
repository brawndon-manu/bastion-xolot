from __future__ import annotations

from typing import Dict, Any
from bastion_agent import enforcement
from bastion_agent.config import PROTECTED_MACS


def handle_event(event: Dict[str, Any]) -> dict:
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

    device_id = event.get("device_id")
    device_id_type = event.get("device_id_type", "mac").lower()
    severity = event.get("severity", "low").lower()
    reason = event.get("reason", "unknown")

    if not device_id:
        raise ValueError("event missing device_id")

    device_id = str(device_id).lower()

    # protected device check
    if device_id_type == "mac" and device_id in {m.lower() for m in PROTECTED_MACS}:
        return {
            "result": {
                "status": "IGNORED",
                "reason": "protected device"
            }
        }

    # Only MAC-identified devices are eligible for enforcement
    if device_id_type != "mac":
        return {
            "result": {
                "status": "IGNORED",
                "reason": f"unresolved device identity ({device_id_type})"
            }
        }

    # POLICY ENGINE (Phase 5 R2)
    if severity == "high":
        return enforcement.request_quarantine_hard(
            mac=device_id,
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