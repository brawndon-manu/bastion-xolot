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

def summarize_system(data: Dict[str, Any]) -> str:
    if not data:
        return "No device activity has been recorded yet."

    total_devices = len(data)
    total_events = sum(device.get("event_count", 0) for device in data.values())
    highest_risk = max(device.get("risk_score", 0) for device in data.values())

    top_mac = max(
        data,
        key=lambda mac: data[mac].get("risk_score", 0)
    )
    top_device = data[top_mac]

    medium_devices = sum(
        1 for device in data.values()
        if device.get("severity_counts", {}).get("medium", 0) > 0
    )

    high_devices = sum(
        1 for device in data.values()
        if device.get("severity_counts", {}).get("high", 0) > 0
    )

    if high_devices > 0:
        overall = "Your network is at elevated risk."
    elif medium_devices > 0:
        overall = "Your network is mostly stable, but some suspicious activity has been observed."
    else:
        overall = "Your network is currently stable with only low-severity activity observed."

    return (
        f"{overall} "
        f"{total_devices} devices have generated {total_events} total events. "
        f"The highest-risk device is {top_mac} with a risk score of {highest_risk}."
    )

def summarize_top_offender(data: Dict[str, Any]) -> str:
    if not data:
        return "No device activity has been recorded yet."

    top_mac = max(
        data,
        key=lambda mac: data[mac].get("risk_score", 0)
    )
    device = data[top_mac]

    risk_score = device.get("risk_score", 0)
    event_count = device.get("event_count", 0)
    severity_counts = device.get("severity_counts", {})

    low = severity_counts.get("low", 0)
    medium = severity_counts.get("medium", 0)
    high = severity_counts.get("high", 0)

    if high > 0:
        reason = "high-severity alerts have been observed"
    elif medium > 0:
        reason = "repeated medium-severity alerts have been observed"
    else:
        reason = "it has generated the most low-severity activity"

    return (
        f"The highest-risk device is {top_mac}. It has triggered {event_count} events "
        f"and currently has a risk score of {risk_score} because {reason}."
    )

def translate_alert_reason(reason: str) -> str:
    reason_lower = reason.lower()

    if "ssdp amplification" in reason_lower:
        return (
            "This device may be sending unusual discovery traffic that can resemble "
            "behavior used in denial-of-service attacks."
        )

    if "session traversal utilities for nat" in reason_lower or "stun" in reason_lower:
        return (
            "This device is using NAT traversal traffic, which is often normal for "
            "voice, video, or real-time communication apps."
        )

    if "dns over https" in reason_lower:
        return (
            "This device is contacting a DNS-over-HTTPS service, which can be normal "
            "but may reduce visibility into DNS activity."
        )

    if "spotify" in reason_lower:
        return (
            "This device is generating Spotify-related network traffic, which is "
            "usually normal media application activity."
        )

    if "discord" in reason_lower:
        return (
            "This device is generating Discord-related network traffic, which is "
            "commonly associated with chat, voice, or media features."
        )

    return (
        "This alert indicates unusual network behavior, but additional context is "
        "needed to determine whether it is truly malicious."
    )

def recommend_action(device: Dict[str, Any]) -> str:
    risk_score = device.get("risk_score", 0)
    severity_counts = device.get("severity_counts", {})

    medium = severity_counts.get("medium", 0)
    high = severity_counts.get("high", 0)

    if high > 0:
        return "Recommendation: Quarantine this device immediately and investigate its recent activity."

    if risk_score >= 20 or medium >= 3:
        return "Recommendation: Monitor this device closely. If suspicious activity continues, quarantine may be necessary."

    return "Recommendation: No immediate action is required. Continue monitoring this device."

def build_intelligence_snapshot(data: Dict[str, Any]) -> Dict[str, Any]:
    if not data:
        return {
            "system_summary": "No device activity has been recorded yet.",
            "top_offender": "No device activity has been recorded yet.",
            "top_offender_recommendation": "Recommendation: No immediate action is required."
        }

    top_mac = max(
        data,
        key=lambda mac: data[mac].get("risk_score", 0)
    )
    top_device = data[top_mac]

    return {
        "system_summary": summarize_system(data),
        "top_offender": summarize_top_offender(data),
        "top_offender_recommendation": recommend_action(top_device)
    }

def render_intelligence_report(snapshot: Dict[str, Any]) -> str:
    recommendation = snapshot.get("top_offender_recommendation", "No immediate action is required.")

    if recommendation.startswith("Recommendation: "):
        recommendation = recommendation[len("Recommendation: "):]

    return (
        "Bastion Intelligence Report\n"
        "---------------------------\n"
        f"System Summary: {snapshot.get('system_summary', 'N/A')}\n\n"
        f"Top Offender: {snapshot.get('top_offender', 'N/A')}\n\n"
        f"Recommendation: {recommendation}"
    )