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


def update_device(mac: str, ip: str | None, severity: str | None = None) -> Dict[str, Any]:
    data = _load()

    now = datetime.utcnow().isoformat()

    # TODO (Phase 6+): Handle "unknown" MAC addresses properly.
    # Currently, unresolved IP → MAC mappings default to "unknown",
    # which causes all unidentified devices to collapse into a single entry.
    # This breaks per-device intelligence, risk scoring, and enforcement accuracy.
    #
    # Future fix ideas:
    # - Use IP as temporary key when MAC is unavailable
    # - Retry ARP resolution before fallback
    # - Maintain separate "unresolved devices" registry
    # - Backfill MAC once discovered

    device = data.get(mac, {
        "mac": mac,
        "name": "unknown",
        "type": "unknown",
        "first_seen": now,
        "last_seen": now,
        "ip": ip,
        "event_count": 0,
        "state": "NONE",
        "risk_score": 0,
        "severity_counts": {
            "low": 0,
            "medium": 0,
            "high": 0
        }
    })

    # ensure new fields exist (schema migration safety)
    if "severity_counts" not in device:
        device["severity_counts"] = {
            "low": 0,
            "medium": 0,
            "high": 0
        }

    if "risk_score" not in device:
        device["risk_score"] = 0

    if "type" not in device:
        device["type"] = "unknown"

    device["last_seen"] = now
    device["ip"] = ip or device.get("ip")
    device["event_count"] += 1
    if severity in device["severity_counts"]:
        device["severity_counts"][severity] += 1
    
    # compute risk score
    low = device["severity_counts"]["low"]
    medium = device["severity_counts"]["medium"]
    high = device["severity_counts"]["high"]

    score = (high * 10) + (medium * 5) + (low * 1)

    device["risk_score"] = min(score, 100)

    data[mac] = device
    _save(data)

    return device

def summarize_device(device: Dict[str, Any]) -> str:
    mac = device.get("mac", "unknown")
    event_count = device.get("event_count", 0)
    risk_score = device.get("risk_score", 0)

    severity_counts = device.get("severity_counts", {})
    low = severity_counts.get("low", 0)
    medium = severity_counts.get("medium", 0)
    high = severity_counts.get("high", 0)

    if high > 0:
        severity_note = "High-severity alerts have been observed."
    elif medium > 0:
        severity_note = "Medium-severity alerts have been observed."
    else:
        severity_note = "Activity has been low severity so far."

    return (
        f"Device {mac} has triggered {event_count} events and currently has "
        f"a risk score of {risk_score}. {severity_note}"
    )