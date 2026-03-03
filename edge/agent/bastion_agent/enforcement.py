"""
Bastión Xólot — Enforcement Engine (Phase 4)

This module owns the full enforcement transaction lifecycle:

1. Determine current device state (desired_state.json)
2. Plan the state transition (compute nft set ops)
3. Snapshot enforcement safety gates
4. Execute nft ops when gates are open
5. Record result (NOOP / PLANNED_ONLY / EXECUTED / FAILED)
6. Append immutable transaction record to local audit journal

Execution Model:
- If no state change is required → result = "NOOP"
- If state change required but gates are closed → result = "PLANNED_ONLY"
- If state change required and gates are open:
    - Success → "EXECUTED"
    - Error → "FAILED"

Safety Properties:
- Idempotent operations (repeated requests are safe)
- Delete of non-existent element is treated as success
- Add of existing element is treated as success
- All transactions recorded append-only (audit trail)

This module is the enforcement state machine entrypoint for the Bastión gateway.
"""

from __future__ import annotations
from typing import Any, Literal, Optional
from bastion_agent import audit
from bastion_agent.config import MONITOR_ONLY, DRY_RUN, ALLOW_ENFORCEMENT
from bastion_agent import state

from bastion_agent.config import enforcement_allowed
from bastion_agent import enforcement_apply


EnfState = Literal["NONE", "SOFT", "HARD"]
ResultStatus = Literal["NOOP", "PLANNED_ONLY", "EXECUTED", "FAILED"]
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

    # Determine planned ops once (used for NOOP / PLANNED_ONLY / EXECUTED)
    ops = tx["plan"]["nft"]["ops"]
    tx["result"]["error"] = None

    # If no changes are required, this is an idempotent request.
    if not ops:
        tx["result"]["status"] = "NOOP"

    # If changes are required but gates are closed, record as planned-only.
    elif not enforcement_allowed():
        tx["result"]["status"] = "PLANNED_ONLY"

    # Gates open and ops exist → execute
    else:
        try:
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
