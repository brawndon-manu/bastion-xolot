from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class NftMembership:
    soft: set[str]
    hard: set[str]


def _run_nft_json(argv: list[str]) -> dict[str, Any]:
    """
    Run an nft command that returns JSON (-j) and parse it.

    Read-only usage only. Raises RuntimeError on failure with stderr included.
    """
    # We call nft via sudo because listing sets may require root depending on system config.
    proc = subprocess.run(
        ["sudo", *argv],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"nft command failed: {' '.join(argv)} :: {proc.stderr.strip()}")

    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"failed to parse nft json output: {exc}") from exc


def _extract_set_elements(nft_json: dict[str, Any]) -> set[str]:
    """
    Extract ether_addr elements from `nft -j list set ...` output.

    The JSON generally looks like:
      {"nftables":[{"metainfo":...}, {"set": {..., "elem":[ ... ] }}]}

    Each elem entry may appear as:
      {"elem": {"val":"aa:bb:..."}}
    or sometimes:
      {"elem":"aa:bb:..."}
    We handle both.

    Returns normalized lowercase MAC strings.
    """
    macs: set[str] = set()

    items = nft_json.get("nftables")
    if not isinstance(items, list):
        return macs

    set_obj: dict[str, Any] | None = None
    for entry in items:
        if isinstance(entry, dict) and "set" in entry and isinstance(entry["set"], dict):
            set_obj = entry["set"]
            break

    if not set_obj:
        return macs

    elems = set_obj.get("elem")
    if not elems:
        return macs
    if not isinstance(elems, list):
        return macs

    for e in elems:
        # Common shape: {"elem": {"val": "aa:bb:..."}}
        if isinstance(e, dict) and "elem" in e:
            inner = e["elem"]
            if isinstance(inner, dict):
                v = inner.get("val")
                if isinstance(v, str):
                    macs.add(v.strip().lower())
                    continue
            if isinstance(inner, str):
                macs.add(inner.strip().lower())
                continue

        # Alternate shape: {"val": "aa:bb:..."} (rare but we accept)
        if isinstance(e, dict):
            v2 = e.get("val")
            if isinstance(v2, str):
                macs.add(v2.strip().lower())
                continue

        # Fallback: raw string element (rare)
        if isinstance(e, str):
            macs.add(e.strip().lower())
            continue

    return macs


def get_quarantine_membership() -> dict[str, set[str]]:
    """
    Read-only snapshot of quarantine membership from nft.

    Returns:
      {"SOFT": set(...), "HARD": set(...)}

    Behavior:
    - If a set doesn't exist, raises RuntimeError (so drift detection can distinguish "empty" vs "broken wiring").
    """
    soft_json = _run_nft_json(["nft", "-j", "list", "set", "inet", "bastion", "quarantine_soft"])
    hard_json = _run_nft_json(["nft", "-j", "list", "set", "inet", "bastion", "quarantine_hard"])

    return {
        "SOFT": _extract_set_elements(soft_json),
        "HARD": _extract_set_elements(hard_json),
    }