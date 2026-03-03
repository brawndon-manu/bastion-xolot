from __future__ import annotations

import re
import subprocess
from typing import Literal

# Op is a TYPE alias: op can only be one of these 4 string values
Op = Literal["ADD_SOFT", "DEL_SOFT", "ADD_HARD", "DEL_HARD"]

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def _validate_mac(mac: str) -> str:
    m = mac.strip().lower()
    if not _MAC_RE.match(m): # prevents running nft with bad input
        raise ValueError(f"invalid mac: {mac}")
    return m  # return normalized validated MAC


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
    - Adding an element that already exists is treated as success. (nice-to-have)
    """
    proc = subprocess.run(
        ["sudo", *argv],
        text=True,
        capture_output=True,
    )

    if proc.returncode == 0:
        return

    stderr = (proc.stderr or "").lower()

    # Narrowly whitelist expected idempotent nft errors
    is_delete_element = ("delete" in argv) and ("element" in argv)
    is_add_element = ("add" in argv) and ("element" in argv)

    if is_delete_element and "element does not exist" in stderr:
        return

    if is_add_element and "element already exists" in stderr:
        return

    # Otherwise: real failure
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

        # important validation of types
        if not isinstance(op, str) or not isinstance(mac, str):
            raise ValueError(f"invalid op entry: {item}")

        argv = build_nft_command(op, mac)  # type: ignore[arg-type]
        commands.append(argv)

        if execute:
            # raises CalledProcessError on failure
            run_command(argv)

    return commands