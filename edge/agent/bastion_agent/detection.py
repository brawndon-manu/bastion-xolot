from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Dict, Any
from bastion_agent import enforcement
from bastion_agent.config import PROTECTED_MACS
from bastion_agent.decision_engine import record_signal, action_tier


STATE_FILE = "/var/lib/bastion/enforcement/desired_state.json"

SOFT_COOLDOWN_SECONDS = 300
HARD_COOLDOWN_SECONDS = 600

# device_id -> cooldown expiry
_COOLDOWNS: dict[str, datetime] = {}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _read_current_state(device_id: str) -> str | None:
    try:
        with open(STATE_FILE, "r") as f:
            data = json.load(f)
        return data.get("devices", {}).get(device_id, {}).get("state")
    except Exception:
        return None


def _cooldown_active(device_id: str) -> bool:
    expiry = _COOLDOWNS.get(device_id)
    if not expiry:
        return False

    if _utcnow() >= expiry:
        del _COOLDOWNS[device_id]
        return False

    return True


def _set_cooldown(device_id: str, seconds: int) -> None:
    _COOLDOWNS[device_id] = _utcnow() + timedelta(seconds=seconds)


def _decision_block(
    event: Dict[str, Any],
    score: int | None = None,
    tier: str | None = None,
    current_state: str | None = None,
    gate: str | None = None,
) -> dict:
    return {
        "source": event.get("source", "unknown"),
        "severity": event.get("severity", "low").lower(),
        "device_id": str(event.get("device_id", "")).lower(),
        "device_id_type": event.get("device_id_type", "mac").lower(),
        "score": score,
        "tier": tier,
        "current_state": current_state,
        "gate": gate,
    }


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
            },
            "decision": _decision_block(event, gate="protected_device"),
        }

    # DECISION ENGINE (Phase 8 R2)
    score = record_signal(event)
    tier = action_tier(score)

    # Only MAC-identified devices are eligible for enforcement
    if device_id_type != "mac":
        return {
            "result": {
                "status": "IGNORED",
                "reason": f"unresolved device identity ({device_id_type})"
            },
            "decision": _decision_block(
                event,
                score=score,
                tier=tier,
                gate="identity_unresolved",
            ),
        }

    current_state = _read_current_state(device_id)

    # ACTION GATES (Phase 8 R4)
    if tier == "hard_quarantine" and current_state == "HARD":
        return {
            "result": {
                "status": "NOOP",
                "reason": "already hard quarantined"
            },
            "decision": _decision_block(
                event,
                score=score,
                tier=tier,
                current_state=current_state,
                gate="already_hard",
            ),
        }

    if tier == "soft_quarantine" and current_state in {"SOFT", "HARD"}:
        return {
            "result": {
                "status": "NOOP",
                "reason": f"already at equal or stronger state ({current_state})"
            },
            "decision": _decision_block(
                event,
                score=score,
                tier=tier,
                current_state=current_state,
                gate="equal_or_stronger_state",
            ),
        }

    # COOLDOWN GATE (Phase 8 R5)
    if tier in {"soft_quarantine", "hard_quarantine"} and _cooldown_active(device_id):
        return {
            "result": {
                "status": "NOOP",
                "reason": "cooldown active"
            },
            "decision": _decision_block(
                event,
                score=score,
                tier=tier,
                current_state=current_state,
                gate="cooldown_active",
            ),
        }

    # POLICY ENGINE (Phase 8 R6)
    if tier == "hard_quarantine":
        _set_cooldown(device_id, HARD_COOLDOWN_SECONDS)
        result = enforcement.request_quarantine_hard(
            mac=device_id,
            reason=reason,
            actor="detection"
        )
        result["decision"] = _decision_block(
            event,
            score=score,
            tier=tier,
            current_state=current_state,
            gate="hard_quarantine_allowed",
        )
        return result

    elif tier == "soft_quarantine":
        _set_cooldown(device_id, SOFT_COOLDOWN_SECONDS)
        return {
            "result": {
                "status": "SOFT_QUARANTINE_CANDIDATE",
                "reason": "score threshold reached"
            },
            "decision": _decision_block(
                event,
                score=score,
                tier=tier,
                current_state=current_state,
                gate="soft_quarantine_allowed",
            ),
        }

    elif tier == "alert":
        return {
            "result": {
                "status": "ALERT_ONLY",
                "reason": "score threshold reached"
            },
            "decision": _decision_block(
                event,
                score=score,
                tier=tier,
                current_state=current_state,
                gate="alert_only",
            ),
        }

    # MONITOR tier -> ignore
    return {
        "result": {
            "status": "IGNORED",
            "reason": "below action threshold"
        },
        "decision": _decision_block(
            event,
            score=score,
            tier=tier,
            current_state=current_state,
            gate="below_threshold",
        ),
    }
