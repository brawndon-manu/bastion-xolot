from __future__ import annotations

from typing import Dict, Any
from bastion_agent import enforcement


def handle_event(event: Dict[str, Any]) -> dict:
    """
    Convert a detection event into an enforcement action.

    Expected event format:
    {
        "type": "suspicious_traffic",
        "mac": "aa:bb:cc:dd:ee:ff",
        "severity": "high" | "medium" | "low",
        "reason": "string"
    }
    """

    mac = event.get("mac")
    severity = event.get("severity", "low")
    reason = event.get("reason", "unknown")

    if not mac:
        raise ValueError("event missing mac")

    # Decision logic (this is your policy engine)
    if severity == "high":
        return enforcement.request_quarantine_hard(mac, reason, actor="detection")

    elif severity == "medium":
        return enforcement.request_quarantine_soft(mac, reason, actor="detection")

    else:
        # low severity → no enforcement
        return {
            "result": {
                "status": "IGNORED",
                "reason": "low severity"
            }
        }