"""
Bastión Xólot — Anomaly Detection Module (Phase 3 + Phase 4)

Compares current device behavior against established baselines to
detect deviations.  Generates alerts with plain-English explanations
and (Phase 4) tags each alert with a recommended enforcement action.

Anomaly types detected:
  - Traffic volume spike  (bytes significantly above baseline)
  - Connection spike      (connection count above baseline)
  - Unusual destinations  (device contacts IPs never seen before)
  - Excessive connections (possible scanning or brute-force)

Severity assignment (drives UI priority per Requirement 4.1.3):
  - low:    mild deviation (z-score 2–3), informational
  - medium: significant spike (z-score 3–4), investigate
  - high:   severe deviation (z-score > 4), possible compromise

Phase 4 — Enforcement Recommendations:
  Each alert includes a `recommended_enforcement` field that maps to
  the Systems Architect's enforcement engine (enforcement.py):
    - low    → no enforcement (continue monitoring)
    - medium → SOFT quarantine recommended
    - high   → HARD quarantine recommended

  The `actor` field is set to the detection module name so the
  audit journal (audit.py) records which module triggered the action.

Satisfies Requirement 1.6:
  "The system shall detect deviations such as: traffic volume spikes,
   unusual destinations, excessive connection attempts."
"""

import json
import logging
from datetime import datetime, timezone

from bastion_agent.baseline import get_baseline, is_baseline_stable
from bastion_agent.events import (
    build_anomaly_detected,
    build_alert,
    enqueue_and_dispatch,
)

logger = logging.getLogger(__name__)

# Z-score thresholds for anomaly severity levels
_Z_LOW = 2.0
_Z_MEDIUM = 3.0
_Z_HIGH = 4.0

# Maximum new destinations before flagging as suspicious
_NEW_DEST_WARN = 3
_NEW_DEST_HIGH = 8


def _z_score(value: float, mean: float, stddev: float) -> float:
    """Compute z-score. Returns 0 if stddev is 0 (no variation observed)."""
    if stddev <= 0:
        return 0.0
    return (value - mean) / stddev


def _severity_from_z(z: float) -> str | None:
    """Map a z-score to an alert severity level, or None if within normal range."""
    if z >= _Z_HIGH:
        return "high"
    if z >= _Z_MEDIUM:
        return "medium"
    if z >= _Z_LOW:
        return "low"
    return None


def _enforcement_for_severity(severity: str) -> dict | None:
    """
    Phase 4: Map alert severity to a recommended enforcement action.

    Returns a dict compatible with the Systems Architect's enforcement
    engine (enforcement.py request_transition), or None.
    """
    if severity == "high":
        return {"state": "HARD", "actor": "anomaly"}
    if severity == "medium":
        return {"state": "SOFT", "actor": "anomaly"}
    return None


def _check_volume_spike(
    flow: dict, baseline: dict, mac: str
) -> list[dict]:
    """Check for outbound byte volume anomalies."""
    events = []
    current = flow["bytes_out"]
    mean = baseline["bytes_out_mean"]
    stddev = baseline["bytes_out_stddev"]
    z = _z_score(current, mean, stddev)
    severity = _severity_from_z(z)

    if severity:
        enforcement = _enforcement_for_severity(severity)

        event = build_anomaly_detected(mac, {
            "anomaly_type": "volume_spike",
            "metric": "bytes_out",
            "current_value": current,
            "baseline_mean": round(mean, 1),
            "baseline_stddev": round(stddev, 1),
            "z_score": round(z, 2),
        })
        enqueue_and_dispatch(event)

        alert = build_alert(
            device_id=mac,
            severity=severity,
            title="Unusual outbound data volume",
            explanation=(
                f"The device {mac} ({flow.get('ip_address', 'unknown IP')}) "
                f"sent {current:,} bytes this interval, which is "
                f"{z:.1f}x the normal variation above its average of "
                f"{mean:,.0f} bytes. This could indicate data exfiltration, "
                f"a backup running at an unusual time, or compromised software "
                f"sending data to an external server."
            ),
            evidence={
                "source_module": "anomaly",
                "details": {
                    "anomaly_type": "volume_spike",
                    "current_bytes": current,
                    "baseline_mean": round(mean, 1),
                    "baseline_stddev": round(stddev, 1),
                    "z_score": round(z, 2),
                    "device_ip": flow.get("ip_address"),
                },
            },
            recommended_action=(
                f"Investigate what the device at {flow.get('ip_address', mac)} "
                f"is sending. Check for unexpected uploads, backups, or "
                f"unfamiliar processes."
            ),
            confidence=min(0.5 + z * 0.1, 0.95),
            related_event_ids=[event["id"]],
        )
        if enforcement:
            alert["recommended_enforcement"] = enforcement
        enqueue_and_dispatch(alert)

        events.extend([event, alert])
        logger.info(
            "Volume spike detected for %s: %d bytes (z=%.1f, severity=%s)",
            mac, current, z, severity,
        )

    return events


def _check_connection_spike(
    flow: dict, baseline: dict, mac: str
) -> list[dict]:
    """Check for connection count anomalies (possible scanning)."""
    events = []
    current = flow["connections"]
    mean = baseline["connections_mean"]
    stddev = baseline["connections_stddev"]
    z = _z_score(current, mean, stddev)
    severity = _severity_from_z(z)

    if severity:
        enforcement = _enforcement_for_severity(severity)

        event = build_anomaly_detected(mac, {
            "anomaly_type": "connection_spike",
            "metric": "connections",
            "current_value": current,
            "baseline_mean": round(mean, 1),
            "baseline_stddev": round(stddev, 1),
            "z_score": round(z, 2),
        })
        enqueue_and_dispatch(event)

        alert = build_alert(
            device_id=mac,
            severity=severity,
            title="Excessive connection attempts",
            explanation=(
                f"The device {mac} ({flow.get('ip_address', 'unknown IP')}) "
                f"made {current} connections this interval, compared to its "
                f"normal average of {mean:.0f}. This is {z:.1f}x the normal "
                f"variation and could indicate port scanning, brute-force "
                f"attempts, or malware trying to spread to other systems."
            ),
            evidence={
                "source_module": "anomaly",
                "details": {
                    "anomaly_type": "connection_spike",
                    "current_connections": current,
                    "baseline_mean": round(mean, 1),
                    "baseline_stddev": round(stddev, 1),
                    "z_score": round(z, 2),
                    "device_ip": flow.get("ip_address"),
                },
            },
            recommended_action=(
                f"Check the device at {flow.get('ip_address', mac)} for "
                f"unfamiliar software or processes making network connections. "
                f"If this device doesn't normally connect to many servers, "
                f"it may be compromised."
            ),
            confidence=min(0.5 + z * 0.1, 0.95),
            related_event_ids=[event["id"]],
        )
        if enforcement:
            alert["recommended_enforcement"] = enforcement
        enqueue_and_dispatch(alert)

        events.extend([event, alert])
        logger.info(
            "Connection spike detected for %s: %d conns (z=%.1f, severity=%s)",
            mac, current, z, severity,
        )

    return events


def _check_unusual_destinations(
    flow: dict, baseline: dict, mac: str
) -> list[dict]:
    """Check for connections to destinations never seen in the baseline."""
    events = []
    current_dests = set(flow.get("destinations", []))
    known_dests = set(baseline.get("known_destinations_list", []))

    new_dests = current_dests - known_dests
    if not new_dests:
        return events

    count = len(new_dests)
    if count < _NEW_DEST_WARN:
        return events

    if count >= _NEW_DEST_HIGH:
        severity = "high"
    elif count >= _NEW_DEST_WARN:
        severity = "medium"
    else:
        severity = "low"

    enforcement = _enforcement_for_severity(severity)
    sample_dests = sorted(new_dests)[:5]  # show up to 5 examples

    event = build_anomaly_detected(mac, {
        "anomaly_type": "unusual_destinations",
        "new_destination_count": count,
        "sample_destinations": sample_dests,
    })
    enqueue_and_dispatch(event)

    alert = build_alert(
        device_id=mac,
        severity=severity,
        title=f"Device contacting {count} new destinations",
        explanation=(
            f"The device {mac} ({flow.get('ip_address', 'unknown IP')}) "
            f"is communicating with {count} IP addresses it has never "
            f"contacted before, including {', '.join(sample_dests)}. "
            f"This is unusual for this device and could indicate "
            f"compromise, new malware communicating with command-and-control "
            f"servers, or a configuration change."
        ),
        evidence={
            "source_module": "anomaly",
            "details": {
                "anomaly_type": "unusual_destinations",
                "new_destination_count": count,
                "new_destinations": sorted(new_dests),
                "known_destination_count": len(known_dests),
                "device_ip": flow.get("ip_address"),
            },
        },
        recommended_action=(
            f"Review the new destinations this device is contacting. "
            f"If you don't recognize them, consider quarantining the "
            f"device until you can investigate further."
        ),
        confidence=min(0.6 + count * 0.05, 0.95),
        related_event_ids=[event["id"]],
    )
    if enforcement:
        alert["recommended_enforcement"] = enforcement
    enqueue_and_dispatch(alert)

    events.extend([event, alert])
    logger.info(
        "Unusual destinations for %s: %d new IPs (severity=%s)",
        mac, count, severity,
    )

    return events


def check_for_anomalies(device_mac: str, current_flow: dict) -> list[dict]:
    """
    Compare a device's current flow summary against its baseline.

    Runs all anomaly checks and returns a list of generated events
    and alerts.  Skips devices whose baselines are still learning.

    Called by the agent main loop after each flow summary collection.
    """
    if not is_baseline_stable(device_mac):
        logger.debug(
            "Baseline for %s still learning — skipping anomaly checks",
            device_mac,
        )
        return []

    baseline = get_baseline(device_mac)
    if not baseline:
        return []

    all_events: list[dict] = []

    all_events.extend(_check_volume_spike(current_flow, baseline, device_mac))
    all_events.extend(_check_connection_spike(current_flow, baseline, device_mac))
    all_events.extend(_check_unusual_destinations(current_flow, baseline, device_mac))

    if all_events:
        logger.info(
            "Anomaly checks for %s: %d events/alerts generated",
            device_mac, len(all_events),
        )

    return all_events
