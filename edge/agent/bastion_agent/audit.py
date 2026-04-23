from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from bastion_agent.utils import utcnow_iso


# Default paths — can be overridden by environment variables.
DEFAULT_STATE_DIR = Path(
    os.getenv("BASTION_ENFORCEMENT_STATE_DIR", "/var/lib/bastion/enforcement")
)
DEFAULT_HISTORY_PATH = Path(
    os.getenv(
        "BASTION_ENFORCEMENT_HISTORY_PATH",
        str(DEFAULT_STATE_DIR / "history.jsonl"),
    )
)


@dataclass(frozen=True)
class AuditPaths:
    state_dir: Path = DEFAULT_STATE_DIR
    history_path: Path = DEFAULT_HISTORY_PATH


def _ensure_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def append_tx(tx: dict[str, Any], paths: AuditPaths = AuditPaths()) -> str:
    """
    Append a single transaction record to the local append-only journal.

    - Adds tx_id if missing
    - Adds ts if missing
    - Writes exactly one line of JSON (NDJSON)
    - fsync ensures the line is on disk before returning

    Safe in monitor-only mode: the transaction result will say
    PLANNED_ONLY, but the record is still written. This is intentional —
    the audit trail captures what the system decided, not just what it did.
    """
    if "tx_id" not in tx or not tx["tx_id"]:
        tx["tx_id"] = str(uuid.uuid4())
    if "ts" not in tx or not tx["ts"]:
        tx["ts"] = utcnow_iso()

    _ensure_parent_dir(paths.history_path)

    line = json.dumps(tx, separators=(",", ":"), ensure_ascii=False)

    # Append-only: open with "a", write one line, fsync for durability.
    # "a" mode means the OS will never overwrite existing content.
    # fsync means the line is physically on disk, not just in a buffer.
    with open(paths.history_path, "a", encoding="utf-8") as f:
        f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())

    return str(tx["tx_id"])


# ---------------------------------------------------------------------------
# OLD FUNCTION: get_audit_history (removed)
# ---------------------------------------------------------------------------
# def get_audit_history(device_id: str | None = None, limit: int = 50) -> list[dict]:
#
# WHY REMOVED:
#   This function filtered by device_id (a string identifier used in the
#   old enforcement.schema.json). Phase 4 uses MAC address as the primary
#   key for device identity, not device_id, because IPs change but MACs
#   follow the device. The new read_history filters by mac to stay
#   consistent with that decision.
#
#   It also planned to read from SQLite. The new implementation reads
#   from the flat NDJSON file instead, which is simpler and matches
#   where append_tx writes.
#
#   Replaced by: read_history(limit, mac)
# ---------------------------------------------------------------------------


def read_history(
    limit: int = 50,
    mac: Optional[str] = None,
    paths: AuditPaths = AuditPaths(),
) -> list[dict[str, Any]]:
    """
    Read the last N transactions from the journal (best-effort).

    If mac is provided, filter to only transactions for that device.
    MAC comparison is case-insensitive.

    Returns an empty list if the journal does not exist yet.
    Skips corrupt lines without crashing — a bad line should never
    take down the agent.
    """
    if not paths.history_path.exists():
        return []

    rows: list[dict[str, Any]] = []
    with open(paths.history_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                # Corrupt line — skip it, do not crash.
                continue

            if mac:
                device = obj.get("device") or {}
                if (device.get("mac") or "").lower() != mac.lower():
                    continue

            rows.append(obj)

    # Return only the last N entries.
    return rows[-limit:]