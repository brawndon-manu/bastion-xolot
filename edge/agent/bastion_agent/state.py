from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Any, Literal, Optional

from bastion_agent.utils import normalize_mac, utcnow_iso

# Devices can only be in these 3 states:
# No enforcement
# Soft quarantine
# Hard quarantine

EnfState = Literal["NONE", "SOFT", "HARD"]
DEFAULT_STATE_DIR = Path(
    os.getenv("BASTION_ENFORCEMENT_STATE_DIR", "/var/lib/bastion/enforcement")
)
DEFAULT_DESIRED_STATE_PATH = Path(
    os.getenv(
        "BASTION_ENFORCEMENT_DESIRED_STATE_PATH",
        str(DEFAULT_STATE_DIR / "desired_state.json"),
    )
)


# filesystem safety: ensure parent directory of the state file exists
def _ensure_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def load_desired_state(path: Path = DEFAULT_DESIRED_STATE_PATH) -> dict[str, Any]:
    if not path.exists():
        return {"version": 1, "updated_at": utcnow_iso(), "devices": {}}

    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        if "devices" not in obj or not isinstance(obj["devices"], dict):
            obj["devices"] = {}
        if "version" not in obj:
            obj["version"] = 1
        return obj
    except json.JSONDecodeError:
        # Corrupt desired state should not brick
        # Start fresh but keep a clear timestamp
        return {"version": 1, "updated_at": utcnow_iso(), "devices": {}}
    
    # safety so it wont crash if folder doesn't exist or if JSON was half written and 
    # a crash happens and adds timestamps with fresh timestamps;
def save_desired_state(obj: dict[str, Any], path: Path = DEFAULT_DESIRED_STATE_PATH) -> None:
    _ensure_parent_dir(path)
    obj["updated_at"] = utcnow_iso()

    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f: # "w" for writing
        json.dump(obj, f, ensure_ascii=False, separators=(",", ":"))
        f.flush() # push python buffer to OS
        os.fsync(f.fileno()) # force OS to commit to disk. dope

        # so now if pi loses power after fsync completes:
        # the temp file is very likely safe on disk and not just in "memory buffer"
        # real file has no change yet

        # ATOMIC REPLACE
    os.replace(tmp, path)

def set_device_state(
        mac: str, 
        state: EnfState, 
        reason: str, 
        actor: str, 
        path: Path=DEFAULT_DESIRED_STATE_PATH) -> dict[str, Any]:
    mac = normalize_mac(mac)
    obj = load_desired_state(path)
    devices = obj.setdefault("devices", {})

    if state == "NONE": # so device gets removed entirely keeping the file clean
        devices.pop(mac, None)
    else:
        devices[mac] = {
            "state": state,
            "reason": reason,
            "actor": actor,
            "updated_at": utcnow_iso(),
        }

    save_desired_state(obj, path)
    return obj

def get_device_state(mac: str, path: Path = DEFAULT_DESIRED_STATE_PATH) -> EnfState:
    mac = normalize_mac(mac)
    obj = load_desired_state(path)
    dev = (obj.get("devices") or {}).get(mac)
    if not dev:
        return "NONE"
    s = dev.get("state")
    return s if s in ("SOFT", "HARD") else "NONE"