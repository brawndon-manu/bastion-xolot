"""
Bastión Xólot — Enforcement Module (Phase 4)

Phase 4 Part 1: Transaction planning + append-only audit (monitor-only safe)

This module does NOT execute nftables yet.
It computes the plan and logs the transaction as PLANNED_ONLY unless
all enforcement gates are explicitly enabled.

--- PHASE 4 UPGRADE NOTES ---
This module was rewritten from its Phase 4 stub. The old stub is preserved
below in comments so the reasoning for each change is clear.

Old module header described:
  - "Detection-side interface for enforcement actions"
  - "Tags alerts with recommended enforcement actions"
  - "Validates that enforcement is safe before requesting it"
  - Enforcement types: quarantine, unquarantine, block_destination, etc.

WHY THE HEADER CHANGED:
  The old framing put this module in a passive advisory role —
  it was going to recommend actions and defer to the Systems Architect
  for actual execution. Phase 4 changes that. This module now owns
  the full transaction lifecycle: build the plan, snapshot the gates,
  write the audit record. Execution (nft calls) comes later in Part 3.
  The module is no longer detection-side only — it is the enforcement
  state machine entry point.
"""

from __future__ import annotations
from typing import Any, Literal, Optional
from bastion_agent import audit
from bastion_agent.config import MONITOR_ONLY, DRY_RUN, ALLOW_ENFORCEMENT
from bastion_agent import state

from bastion_agent.config import enforcement_allowed
from bastion_agent import enforcement_apply


EnfState = Literal["NONE", "SOFT", "HARD"]
Op = Literal["ADD_SOFT", "DEL_SOFT", "ADD_HARD", "DEL_HARD"]


def _normalize_mac(mac: str) -> str:
    return mac.strip().lower()


def _gates_snapshot() -> dict[str, bool]:
    """
    Capture the current state of all three safety gates.

    This snapshot is written into every transaction record so there is
    permanent proof of what the gate state was when the decision was made.
    """
    return {
        "monitor_only": bool(MONITOR_ONLY),
        "dry_run": bool(DRY_RUN),
        "allow_enforcement": bool(ALLOW_ENFORCEMENT),
    }


def _plan_ops(
    mac: str, from_state: EnfState, to_state: EnfState
) -> list[dict[str, str]]:
    """
    Compute nft set membership operations needed for a state transition.

    IMPORTANT:
    - Set-level planning only — no chain edits, no base table changes.
    - Transitions are explicit and minimal.
    - A NONE → NONE transition produces zero ops (no-op).
    """
    mac = _normalize_mac(mac)
    ops: list[dict[str, str]] = []

    if from_state == to_state:
        return ops

    # Remove from prior state set if applicable
    if from_state == "SOFT":
        ops.append({"op": "DEL_SOFT", "mac": mac})
    elif from_state == "HARD":
        ops.append({"op": "DEL_HARD", "mac": mac})

    # Add to target state set if applicable
    if to_state == "SOFT":
        ops.append({"op": "ADD_SOFT", "mac": mac})
    elif to_state == "HARD":
        ops.append({"op": "ADD_HARD", "mac": mac})

    return ops


def plan_transition(
    mac: str,
    from_state: EnfState,
    to_state: EnfState,
    reason: str,
    actor: str = "manual",
    ip_last_seen: Optional[str] = None,
    iface: Optional[str] = None,
    label: Optional[str] = None,
) -> dict[str, Any]:
    """
    Assemble a transaction dict matching enforcement_transaction.schema.json.

    Pure planning function — no side effects, no file writes, no nft calls.
    Separating planning from execution means we can inspect, test, and log
    the plan independently of whether it runs.
    """
    mac_norm = _normalize_mac(mac)
    gates = _gates_snapshot()
    ops = _plan_ops(mac_norm, from_state, to_state)

    # tx is transaction which represents: One requested state change for one device
    tx: dict[str, Any] = {
        # tx_id and ts are added by audit.append_tx if missing
        "device": {
            "mac": mac_norm,
            "ip_last_seen": ip_last_seen,
            "iface": iface,
            "label": label,
        },
        "transition": {
            "from": from_state,
            "to": to_state,
            "reason": reason,
            "actor": actor,
        },
        "gates": gates,
        "plan": {
            "nft": {
                "table": "inet bastion",
                "ops": ops,
            }
        },
        "result": {
            "status": "PLANNED_ONLY",
            "error": None,
        },
    }

    return tx

"""
request_transition()

- determine current state
- plan the transition
- update desired_state.json
- possibly execute nft ops
- record result
- append to audit log
"""
def request_transition(
    mac: str,
    to_state: EnfState,
    reason: str,
    actor: str = "manual",
    ip_last_seen: Optional[str] = None,
    iface: Optional[str] = None,
    label: Optional[str] = None,
) -> dict[str, Any]:
    """
    State-machine entrypoint (Part 1):
    - reads desired state to determine actual from_state
    - updates desired_state.json
    - logs a transaction as PLANNED_ONLY

    NOTE: from_state argument is ignored in favor of desired state.
    """
    current = state.get_device_state(mac)
    tx = plan_transition(
        mac=mac,
        from_state=current,  # changed from "from_state=from_state"
        to_state=to_state,
        reason=reason,
        actor=actor,
        ip_last_seen=ip_last_seen,
        iface=iface,
        label=label,
    )
    # Updated desired state (even in monitor-only) this is "desired", not "applied"
    state.set_device_state(mac, to_state, reason=reason, actor=actor)

    # Part 1 contract: never execute. Always planned-only.
    tx["result"]["status"] = "PLANNED_ONLY"
    tx["result"]["error"] = None

    # If and only if gates are open, execute the planned ops.
    if enforcement_allowed():
        try:
            ops = tx["plan"]["nft"]["ops"]
            enforcement_apply.apply_ops(ops, execute=True)
            tx["result"]["status"] = "EXECUTED"
        except Exception as exc:
            tx["result"]["status"] = "FAILED"
            tx["result"]["error"] = str(exc)

    tx_id = audit.append_tx(tx)
    tx["tx_id"] = tx_id
    return tx


# Convenience wrappers — public enforcement entrypoints.
#
# IMPORTANT:
# - Callers provide ONLY the target state.
# - The authoritative "from_state" is read from desired_state.json.
# - This guarantees transaction logs reflect actual state transitions,
#   not caller assumptions.


def request_quarantine_soft(
    mac: str, reason: str, actor: str = "manual"
) -> dict[str, Any]:
    """
    Transition device to SOFT quarantine.

    The previous state is determined internally from desired_state.json.
    """
    return request_transition(mac, "SOFT", reason, actor=actor)


def request_quarantine_hard(
    mac: str, reason: str, actor: str = "manual"
) -> dict[str, Any]:
    """
    Transition device to HARD quarantine.

    The previous state is determined internally from desired_state.json.
    """
    return request_transition(mac, "HARD", reason, actor=actor)


def request_unquarantine(
    mac: str, reason: str, actor: str = "manual"
) -> dict[str, Any]:
    """
    Transition device back to NONE (fully unquarantined).

    The previous state is determined internally from desired_state.json.
    """
    return request_transition(mac, "NONE", reason, actor=actor)
