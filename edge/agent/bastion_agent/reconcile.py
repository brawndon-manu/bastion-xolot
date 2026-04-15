from __future__ import annotations

from typing import Dict, List

from bastion_agent import state, audit, enforcement_runtime
from bastion_agent.config import enforcement_allowed
from bastion_agent.enforcement_plan import plan_ops
from bastion_agent.nft_state import get_quarantine_membership


MAX_OPS = 10  # safety guardrail

def _desired_membership() -> Dict[str, set[str]]:
    """
    Build desired membership sets from desired_state.json
    """
    soft: set[str] = set()
    hard: set[str] = set()

    obj = state.load_desired_state()
    devices = obj.get("devices", {})

    for mac, info in devices.items():
        if not isinstance(info, dict):
            continue

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

    for mac in desired["HARD"] - actual["HARD"]:
        ops.extend(plan_ops(mac, "NONE", "HARD"))
    for mac in actual["HARD"] - desired["HARD"]:
        ops.extend(plan_ops(mac, "HARD", "NONE"))

    for mac in desired["SOFT"] - actual["SOFT"]:
        ops.extend(plan_ops(mac, "NONE", "SOFT"))
    for mac in actual["SOFT"] - desired["SOFT"]:
        ops.extend(plan_ops(mac, "SOFT", "NONE"))

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

    # too many changes -> safety stop
    elif len(ops) > MAX_OPS:
        tx["result"]["status"] = "FAILED"
        tx["result"]["error"] = f"too many ops: {len(ops)}"

    # gates closed
    elif not enforcement_allowed():
        tx["result"]["status"] = "PLANNED_ONLY"

    else:
        tx["result"].update(enforcement_runtime.execute_ops(ops))

    tx_id = audit.append_tx(tx)
    tx["tx_id"] = tx_id
    return tx