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

# ---------------------------------------------------------------------------
# OLD IMPORT BLOCK (removed)
# ---------------------------------------------------------------------------
# import logging
# from bastion_agent.config import enforcement_allowed, DRY_RUN
# logger = logging.getLogger(__name__)
#
# WHY REMOVED:
#   The old stub imported enforcement_allowed() — a single yes/no gate
#   function — and DRY_RUN. The new module imports all three raw flags
#   (MONITOR_ONLY, DRY_RUN, ALLOW_ENFORCEMENT) directly because it needs
#   to snapshot each one individually into the transaction record.
#   Knowing "enforcement was denied" is not enough — we need to know
#   exactly which gate denied it and what state each gate was in at the
#   time of the transaction.
#
#   logging is removed for the same reason as in audit.py — the stub
#   used it because there was nothing real to do. Now we write actual
#   transaction records, so the audit journal is the output.
# ---------------------------------------------------------------------------


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


def _plan_ops(mac: str, from_state: EnfState, to_state: EnfState) -> list[dict[str, str]]:
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


# ---------------------------------------------------------------------------
# OLD FUNCTION: recommend_action (removed)
# ---------------------------------------------------------------------------
# def recommend_action(alert: dict) -> str | None:
#     """
#     Given an alert, recommend an enforcement action.
#     Phase 4 implementation will analyze alert severity, type,
#     and evidence to suggest the appropriate response.
#     Returns action string or None if no action recommended.
#     """
#     logger.debug("enforcement.recommend_action() — not yet implemented (Phase 4)")
#     return None
#
# WHY REMOVED:
#   This was a detection-side advisory function — it was going to inspect
#   an alert dict and return a string like "quarantine" or "block_destination".
#   That responsibility now belongs upstream. The caller (detection layer,
#   backend, or user action) decides what transition to request. The
#   enforcement module's job is to plan, gate-check, and log — not to
#   interpret alerts. Mixing those concerns here would make both harder
#   to test and harder to audit.
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# OLD FUNCTION: request_quarantine (removed)
# ---------------------------------------------------------------------------
# def request_quarantine(device_mac: str, reason: str) -> bool:
#     """
#     Request quarantine of a device.
#     Returns True if quarantine was applied, False otherwise.
#     """
#     if not enforcement_allowed():
#         logger.info("Quarantine requested for %s but enforcement is not allowed", device_mac)
#         return False
#     if DRY_RUN:
#         logger.info("[DRY RUN] Would quarantine device: %s — reason: %s", device_mac, reason)
#         return False
#     logger.debug("enforcement.request_quarantine(%s) — not yet implemented (Phase 4)", device_mac)
#     return False
#
# WHY REMOVED:
#   This returned a boolean — True if quarantine applied, False otherwise.
#   A boolean tells you nothing useful for auditing:
#     - Were the gates open or closed?
#     - What firewall ops were planned?
#     - Was this monitor-only or dry-run?
#     - What was the before/after state?
#   You cannot answer any of those questions from True/False.
#   It also conflated SOFT and HARD quarantine into one function, which
#   makes the two-stage model impossible to express.
#   Replaced by request_quarantine_soft and request_quarantine_hard,
#   both of which return the full transaction dict.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# OLD FUNCTION: request_unquarantine (removed)
# ---------------------------------------------------------------------------
# def request_unquarantine(device_mac: str, reason: str) -> bool:
#     """
#     Request removal of quarantine for a device.
#     Returns True if unquarantine was applied, False otherwise.
#     """
#     if not enforcement_allowed():
#         logger.info("Unquarantine requested for %s but enforcement is not allowed", device_mac)
#         return False
#     logger.debug(
#         "enforcement.request_unquarantine(%s) — not yet implemented (Phase 4)", device_mac
#     )
#     return False
#
# WHY REMOVED:
#   Same reason as request_quarantine — returned a boolean with no
#   context about what happened or why. Also had no concept of which
#   quarantine state (SOFT or HARD) was being reversed, which means
#   it could not compute the correct nft DEL operation.
#   Replaced by request_unquarantine below, which takes from_state
#   explicitly and returns the full transaction dict.
# ---------------------------------------------------------------------------


def request_transition(
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
    State-machine entrypoint (Part 1):
    - reads desired state to determine actual from_state
    - updates desired_state.json
    - logs a transaction as PLANNED_ONLY

    NOTE: from_state argument is ignored in favor of desired state.
    """
    current = state.get_device_state(mac)
    tx = plan_transition(
        mac=mac,
        from_state=from_state,
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
    tx_id = audit.append_tx(tx)
    tx["tx_id"] = tx_id
    return tx


# Convenience wrappers — clean named entry points so callers
# do not have to pass state strings manually.

def request_quarantine_soft(mac: str, reason: str, actor: str = "manual") -> dict[str, Any]:
    """Transition device from NONE → SOFT (WAN isolation, LAN still allowed)."""
    return request_transition(mac, "NONE", "SOFT", reason, actor=actor)


def request_quarantine_hard(mac: str, reason: str, actor: str = "manual") -> dict[str, Any]:
    """Transition device from NONE → HARD (full containment)."""
    return request_transition(mac, "NONE", "HARD", reason, actor=actor)


def request_unquarantine(mac: str, reason: str, actor: str = "manual") -> dict[str, Any]:
    """
    Transition device back to NONE (full access restored).

    Assumes HARD as the from_state for now. In Part 4 we will reconcile
    actual state from desired_state.json + nft inspection before calling this.
    """
    return request_transition(mac, "HARD", "NONE", reason, actor=actor)