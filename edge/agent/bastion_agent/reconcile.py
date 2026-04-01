from __future__ import annotations

from typing import Dict, List

from bastion_agent import state, audit, enforcement_apply
from bastion_agent.config import enforcement_allowed
from bastion_agent.nft_state import get_quarantine_membership


MAX_OPS = 10  # safety guardrail


def _desired_membership() -> Dict[str, set[str]]:
    """
    Build desired membership sets from desired_state.json
    """
    soft: set[str] = set()
    hard: set[str] = set()

    devices = state._load_state().get("devices", {})

    for mac, info in devices.items():
        s = info.get("state")
        if s == "SOFT":
            soft.add(mac)
        elif s == "HARD":
            hard.add(mac)

    return {"SOFT": soft, "HARD": hard}


def _diff_ops(desired: Dict[str, set[str]], actual: Dict[str, set[str]]) -> List[dict]:
    """
    Compute minimal nft ops to reconcile actual → desired
    """
    ops: List[dict] = []

    # HARD set
    for mac in desired["HARD"] - actual["HARD"]:
        ops.append({"op": "ADD_HARD", "mac": mac})
    for mac in actual["HARD"] - desired["HARD"]:
        ops.append({"op": "DEL_HARD", "mac": mac})

    # SOFT set
    for mac in desired["SOFT"] - actual["SOFT"]:
        ops.append({"op": "ADD_SOFT", "mac": mac})
    for mac in actual["SOFT"] - desired["SOFT"]:
        ops.append({"op": "DEL_SOFT", "mac": mac})

    return ops


def reconcile_once() -> dict:
    """
    Perform a single reconciliation pass.

    Returns a transaction-like dict for audit.
    """
    desired = _desired_membership()
    actual = get_quarantine_membership()

    ops = _diff_ops(desired, actual)

    tx = {
        "device": {"mac": None},
        "transition": {
            "from": "MIXED",
            "to": "MIXED",
            "reason": "reconcile",
            "actor": "system",
        },
        "gates": {
            "monitor_only": None,
            "dry_run": None,
            "allow_enforcement": enforcement_allowed(),
        },
        "plan": {"nft": {"table": "inet bastion", "ops": ops}},
        "result": {"status": None, "error": None},
    }

    # NOOP
    if not ops:
        tx["result"]["status"] = "NOOP"

    # too many changes → safety stop
    elif len(ops) > MAX_OPS:
        tx["result"]["status"] = "FAILED"
        tx["result"]["error"] = f"too many ops: {len(ops)}"

    # gates closed
    elif not enforcement_allowed():
        tx["result"]["status"] = "PLANNED_ONLY"

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