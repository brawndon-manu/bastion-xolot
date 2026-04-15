from __future__ import annotations

import os
import subprocess
from typing import Literal

from bastion_agent.utils import normalize_mac, is_valid_mac

Op = Literal["ADD_SOFT", "DEL_SOFT", "ADD_HARD", "DEL_HARD"]


def _validate_mac(mac: str) -> str:
    m = normalize_mac(mac)
    if not is_valid_mac(m):
        raise ValueError(f"invalid mac: {mac}")
    return m


def build_nft_command(op: Op, mac: str) -> list[str]:
    """
    Translate a single planned op into a single nft command (argv list).
    No shell, no free-form input, no chain edits.
    """
    mac = _validate_mac(mac)

    if op == "ADD_SOFT":
        return ["nft", "add", "element", "inet", "bastion", "quarantine_soft", "{", mac, "}"]
    if op == "DEL_SOFT":
        return ["nft", "delete", "element", "inet", "bastion", "quarantine_soft", "{", mac, "}"]
    if op == "ADD_HARD":
        return ["nft", "add", "element", "inet", "bastion", "quarantine_hard", "{", mac, "}"]
    if op == "DEL_HARD":
        return ["nft", "delete", "element", "inet", "bastion", "quarantine_hard", "{", mac, "}"]

    raise ValueError(f"unknown op: {op}")


def run_command(argv: list[str]) -> None:
    """
    Execute the command safely.

    Idempotency rules:
    - Deleting an element that does not exist is treated as success.
    - Adding an element that already exists is treated as success.
    """
    cmd = argv if os.geteuid() == 0 else ["sudo", *argv]

    proc = subprocess.run(cmd, text=True, capture_output=True)

    if proc.returncode == 0:
        return

    stderr = (proc.stderr or "").lower()

    is_delete_element = ("delete" in argv) and ("element" in argv)
    is_add_element = ("add" in argv) and ("element" in argv)

    if is_delete_element and "element does not exist" in stderr:
        return

    if is_add_element and "element already exists" in stderr:
        return

    raise subprocess.CalledProcessError(
        proc.returncode,
        proc.args,
        output=proc.stdout,
        stderr=proc.stderr,
    )


def apply_ops(ops: list[dict[str, str]], *, execute: bool) -> list[list[str]]:
    """
    Apply a list of nft ops of the form: {"op": "...", "mac": "..."}.

    Returns the argv commands (for audit/debug).
    If execute=False: does not run anything.
    If execute=True: runs commands in order, raises on first failure.
    """
    commands: list[list[str]] = []

    for item in ops:
        op = item.get("op")
        mac = item.get("mac")

        if not isinstance(op, str) or not isinstance(mac, str):
            raise ValueError(f"invalid op entry: {item}")

        argv = build_nft_command(op, mac)  # type: ignore[arg-type]
        commands.append(argv)

        if execute:
            run_command(argv)

    return commands
