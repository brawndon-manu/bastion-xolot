from __future__ import annotations

import ipaddress
import os
import subprocess
from typing import Literal

Op = Literal["ADD_SOFT", "DEL_SOFT", "ADD_HARD", "DEL_HARD"]


def _validate_ip(ip: str) -> str:
    try:
        return str(ipaddress.IPv4Address(ip.strip()))
    except ValueError:
        raise ValueError(f"invalid ipv4 address: {ip}")


def build_nft_command(op: Op, ip: str) -> list[str]:
    """
    Translate a single planned op into a single nft command (argv list).
    No shell, no free-form input, no chain edits.
    Sets are now ipv4_addr type — we match on IP not MAC.
    """
    ip = _validate_ip(ip)

    if op == "ADD_SOFT":
        return ["nft", "add", "element", "inet", "bastion", "quarantine_soft", "{", ip, "}"]
    if op == "DEL_SOFT":
        return ["nft", "delete", "element", "inet", "bastion", "quarantine_soft", "{", ip, "}"]
    if op == "ADD_HARD":
        return ["nft", "add", "element", "inet", "bastion", "quarantine_hard", "{", ip, "}"]
    if op == "DEL_HARD":
        return ["nft", "delete", "element", "inet", "bastion", "quarantine_hard", "{", ip, "}"]

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
