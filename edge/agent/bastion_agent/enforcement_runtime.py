"""
Bastión Xólot — Enforcement Runtime

Shared side-effect helpers: executes planned nft ops and returns a result
dict.  Isolates the try/except and result-dict assembly in one place so
enforcement.py and reconcile.py stay consistent and can't drift.
"""
from __future__ import annotations
from bastion_agent import enforcement_apply


def execute_ops(ops: list[dict]) -> dict:
    """
    Run planned nft ops and return a result dict.

    Returns:
        {"status": "EXECUTED", "error": None}  on success
        {"status": "FAILED",   "error": str}   on failure
    """
    try:
        enforcement_apply.apply_ops(ops, execute=True)
        return {"status": "EXECUTED", "error": None}
    except Exception as exc:
        return {"status": "FAILED", "error": str(exc)}
