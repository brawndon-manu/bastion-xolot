"""
Bastión Xólot — Enforcement Planner

Pure state-transition planning: maps (mac, from_state, to_state) to a list
of nft set-membership ops.  No side effects, no file I/O, no nft calls.

Both enforcement.py (single-device) and reconcile.py (bulk) delegate here
so the state-machine lives in exactly one place.
"""
from __future__ import annotations
from typing import Literal
from bastion_agent.utils import normalize_mac

EnfState = Literal["NONE", "SOFT", "HARD"]


def plan_ops(mac: str, from_state: EnfState, to_state: EnfState) -> list[dict]:
    """
    Compute nft set membership operations needed for a state transition.

    - Set-level planning only: no chain edits, no base table changes.
    - Transitions are explicit and minimal.
    - NONE → NONE produces zero ops.
    """
    mac = normalize_mac(mac)
    ops: list[dict] = []

    if from_state == to_state:
        return ops

    if from_state == "SOFT":
        ops.append({"op": "DEL_SOFT", "mac": mac})
    elif from_state == "HARD":
        ops.append({"op": "DEL_HARD", "mac": mac})

    if to_state == "SOFT":
        ops.append({"op": "ADD_SOFT", "mac": mac})
    elif to_state == "HARD":
        ops.append({"op": "ADD_HARD", "mac": mac})

    return ops
