from __future__ import annotations

from typing import Dict, List

from bastion_agent import state, audit, enforcement_runtime
from bastion_agent.config import enforcement_allowed, operator_enforcement_allowed
from bastion_agent.nft_state import get_quarantine_membership
from bastion_agent.storage import get_known_device


MAX_OPS = 10  # safety guardrail


def _desired_membership() -> Dict[str, set[str]]:
    """
    Build desired membership sets from desired_state.json.

    Keys in desired_state are MACs (stable identity); nft sets hold IPs.
    We resolve each MAC to its current IP via the local DB and skip devices
    whose IP is unknown (offline or not yet seen).
    """
    soft: set[str] = set()
    hard: set[str] = set()

    obj = state.load_desired_state()
    devices = obj.get("devices", {})

    for mac, info in devices.items():
        if not isinstance(info, dict):
            continue
        s = info.get("state")
        if s not in ("SOFT", "HARD"):
            continue
        device = get_known_device(mac)
        if not device or not device.get("ip_address"):
            continue  # can't enforce without an IP — skip until device reappears
        ip = device["ip_address"]
        if s == "SOFT":
            soft.add(ip)
        elif s == "HARD":
            hard.add(ip)

    return {"SOFT": soft, "HARD": hard}


def _operator_ips() -> set[str]:
    """
    Return IPs whose last desired-state change was operator-initiated.

    Includes NONE-state entries so that operator-triggered releases also
    route through the operator gate (bypassing monitor-only).
    """
    obj = state.load_desired_state()
    ips: set[str] = set()
    for mac, info in (obj.get("devices") or {}).items():
        if isinstance(info, dict) and info.get("actor") == "operator":
            device = get_known_device(mac)
            if device and device.get("ip_address"):
                ips.add(device["ip_address"])
    return ips


def _diff_ops(desired: Dict[str, set[str]], actual: Dict[str, set[str]]) -> List[dict]:
    """
    Compute minimal nft ops to reconcile actual → desired.
    Both sets contain IP addresses. The op dict uses "mac" as the key name
    for historical compat — enforcement_apply.py reads it as an IP.
    """
    ops: List[dict] = []

    for ip in desired["HARD"] - actual["HARD"]:
        ops.append({"op": "ADD_HARD", "mac": ip})
    for ip in actual["HARD"] - desired["HARD"]:
        ops.append({"op": "DEL_HARD", "mac": ip})

    for ip in desired["SOFT"] - actual["SOFT"]:
        ops.append({"op": "ADD_SOFT", "mac": ip})
    for ip in actual["SOFT"] - desired["SOFT"]:
        ops.append({"op": "DEL_SOFT", "mac": ip})

    return ops


def reconcile_once() -> dict:
    """
    Perform a single reconciliation pass.

    Operator-initiated entries in desired_state.json are enforced even when
    monitor-only mode is on. System entries respect the monitor-only gate.
    """
    desired = _desired_membership()
    actual = get_quarantine_membership()
    all_ops = _diff_ops(desired, actual)

    if not all_ops:
        tx = {
            "device": {"mac": None},
            "transition": {
                "from": "MIXED",
                "to": "MIXED",
                "reason": "reconcile",
                "actor": "system",
            },
            "gates": {"allow_enforcement": enforcement_allowed()},
            "plan": {"nft": {"table": "inet bastion", "ops": []}},
            "result": {"status": "NOOP", "error": None},
        }
        tx["tx_id"] = audit.append_tx(tx)
        return tx

    if len(all_ops) > MAX_OPS:
        tx = {
            "device": {"mac": None},
            "transition": {
                "from": "MIXED",
                "to": "MIXED",
                "reason": "reconcile",
                "actor": "system",
            },
            "gates": {"allow_enforcement": enforcement_allowed()},
            "plan": {"nft": {"table": "inet bastion", "ops": all_ops}},
            "result": {"status": "FAILED", "error": f"too many ops: {len(all_ops)}"},
        }
        tx["tx_id"] = audit.append_tx(tx)
        return tx

    # Split ops: operator-initiated IPs bypass monitor-only
    operator_ips = _operator_ips()
    operator_ops = [op for op in all_ops if op.get("mac") in operator_ips]
    system_ops = [op for op in all_ops if op.get("mac") not in operator_ips]

    executed_ops = []
    planned_ops = []

    if operator_ops and operator_enforcement_allowed():
        executed_ops.extend(operator_ops)
    else:
        planned_ops.extend(operator_ops)

    if system_ops and enforcement_allowed():
        executed_ops.extend(system_ops)
    else:
        planned_ops.extend(system_ops)

    result: dict = {"status": None, "error": None}
    if executed_ops:
        result.update(enforcement_runtime.execute_ops(executed_ops))
    if not executed_ops and planned_ops:
        result["status"] = "PLANNED_ONLY"
    elif not executed_ops and not planned_ops:
        result["status"] = "NOOP"

    tx = {
        "device": {"mac": None},
        "transition": {
            "from": "MIXED",
            "to": "MIXED",
            "reason": "reconcile",
            "actor": "system",
        },
        "gates": {
            "allow_enforcement": enforcement_allowed(),
            "operator_enforcement_allowed": operator_enforcement_allowed(),
        },
        "plan": {"nft": {"table": "inet bastion", "ops": all_ops}},
        "executed_ops": executed_ops,
        "planned_only_ops": planned_ops,
        "result": result,
    }
    tx["tx_id"] = audit.append_tx(tx)
    return tx
