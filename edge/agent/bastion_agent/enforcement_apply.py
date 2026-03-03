from __future__ import annotations

import re
import subprocess
from typing import Literal

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
    Execute the command. Intended for Pi runtime later.
    Raises CalledProcessError on failure.
    """
    # Prefix argv with sudo, run it, and fail loudly on errors
    subprocess.run(["sudo", *argv], check=True)