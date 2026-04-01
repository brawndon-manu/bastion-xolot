from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Dict, Any

DEVICE_FILE = "/var/lib/bastion/devices/devices.json"


def _load() -> Dict[str, Any]:
    if not os.path.exists(DEVICE_FILE):
        return {}

    try:
        with open(DEVICE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def _save(data: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(DEVICE_FILE), exist_ok=True)

    with open(DEVICE_FILE, "w") as f:
        json.dump(data, f, indent=2)


def update_device(mac: str, ip: str | None) -> Dict[str, Any]:
    data = _load()

    now = datetime.utcnow().isoformat()

    device = data.get(mac, {
        "mac": mac,
        "name": "unknown",
        "first_seen": now,
        "last_seen": now,
        "ip": ip,
        "event_count": 0,
        "state": "NONE"
    })

    # update fields
    device["last_seen"] = now
    device["ip"] = ip or device.get("ip")
    device["event_count"] += 1

    data[mac] = device
    _save(data)

    return device