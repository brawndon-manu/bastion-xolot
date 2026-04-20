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
import time
from datetime import datetime, timezone
from bastion_agent.config import GATEWAY_IP
from bastion_agent.detection import handle_event

from bastion_agent.baseline import get_baseline, is_baseline_stable
from bastion_agent.storage import load_cooldowns, save_cooldown
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

# Minimum new destinations before flagging as suspicious
_NEW_DEST_WARN = 15
_NEW_DEST_HIGH = 40

# Cooldown: seconds before the same alert type can fire again for the same device
_ALERT_COOLDOWN_SECS = 3600

# Cooldown tracker: (mac, alert_type) → last fired wall-clock timestamp.
# Populated from DB at startup via init_cooldowns(); written through on every fire.
_cooldown: dict[tuple[str, str], float] = {}


def init_cooldowns() -> None:
    """Load persisted cooldown state from the local DB. Call once at startup."""
    _cooldown.update(load_cooldowns())
    logger.info("Loaded %d alert cooldown entries from DB", len(_cooldown))


def _is_on_cooldown(mac: str, alert_type: str) -> bool:
    key = (mac, alert_type)
    last = _cooldown.get(key, 0.0)
    return (time.time() - last) < _ALERT_COOLDOWN_SECS


def _mark_cooldown(mac: str, alert_type: str) -> None:
    now = time.time()
    _cooldown[(mac, alert_type)] = now
    try:
        save_cooldown(mac, alert_type, now)
    except Exception:
        logger.warning("Failed to persist cooldown for %s / %s", mac, alert_type)


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

def _should_alert(severity: str, mac: str = "", alert_type: str = "") -> bool:
    """Only medium/high anomalies that aren't on cooldown generate user-facing alerts."""
    if severity not in {"medium", "high"}:
        return False
    if mac and alert_type:
        if _is_on_cooldown(mac, alert_type):
            logger.debug("Alert suppressed (cooldown): %s / %s", mac, alert_type)
            return False
        _mark_cooldown(mac, alert_type)
    return True


def _confidence_from_z(z: float, severity: str) -> float:
    """Map anomaly strength into a more stable confidence score."""
    if severity == "high":
        return min(0.80 + max(z - _Z_HIGH, 0) * 0.03, 0.95)
    if severity == "medium":
        return min(0.65 + max(z - _Z_MEDIUM, 0) * 0.04, 0.85)
    return min(0.45 + max(z - _Z_LOW, 0) * 0.03, 0.60)


def _confidence_from_count(count: int, severity: str) -> float:
    """Map unusual-destination count into a stable confidence score."""
    if severity == "high":
        return min(0.80 + max(count - _NEW_DEST_HIGH, 0) * 0.02, 0.95)
    if severity == "medium":
        return min(0.65 + max(count - _NEW_DEST_WARN, 0) * 0.03, 0.85)
    return 0.50

def _route_to_detection(mac: str, severity: str, reason: str) -> None:
    """
    Send a normalized event into the central detection policy engine.
    Fail open: alert generation should continue even if policy routing fails.
    """
    try:
        result = handle_event({
            "device_id": mac,
            "device_id_type": "mac",
            "severity": severity,
            "reason": reason,
        })
        logger.info(
            "Detection policy result for %s: %s",
            mac,
            result.get("result", {}).get("status", "unknown"),
        )
    except Exception:
        logger.exception("Failed routing anomaly signal into detection engine for %s", mac)
        
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
        events.append(event)

        if _should_alert(severity, mac, "volume_spike"):
            _route_to_detection(
                mac,
                severity,
                f"volume_spike z={z:.2f} bytes_out={current}"
            )

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
                confidence=_confidence_from_z(z, severity),
                related_event_ids=[event["id"]],
            )
            if enforcement:
                alert["recommended_enforcement"] = enforcement
            enqueue_and_dispatch(alert)
            events.append(alert)

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
        events.append(event)

        if _should_alert(severity, mac, "connection_spike"):
            _route_to_detection(
                mac,
                severity,
                f"connection_spike z={z:.2f} connections={current}"
            )

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
                confidence=_confidence_from_z(z, severity),
                related_event_ids=[event["id"]],
            )
            if enforcement:
                alert["recommended_enforcement"] = enforcement
            enqueue_and_dispatch(alert)
            events.append(alert)

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

    if _is_on_cooldown(mac, "unusual_destinations"):
        logger.debug("Alert suppressed (cooldown): %s / unusual_destinations", mac)
        return events
    _mark_cooldown(mac, "unusual_destinations")

    enforcement = _enforcement_for_severity(severity)

    _route_to_detection(
        mac,
        severity,
        f"unusual_destinations count={count}"
    )

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
        confidence=_confidence_from_count(count, severity),
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

    Runs deterministic scan/probe checks even during baseline learning.
    Baseline-dependent checks are skipped until the baseline is stable.

    Called by the agent main loop after each flow summary collection.
    """
    all_events: list[dict] = []

    # Phase 9A:
    # Run deterministic probe detection even if the statistical baseline
    # is still learning. This rule does not depend on baseline math.
    all_events.extend(_check_scan_probe(current_flow, device_mac))

    if not is_baseline_stable(device_mac):
        if all_events:
            logger.info(
                "Anomaly checks for %s: %d events/alerts generated (baseline learning; baseline-dependent checks skipped)",
                device_mac, len(all_events),
            )
        else:
            logger.debug(
                "Baseline for %s still learning — skipping baseline-dependent anomaly checks",
                device_mac,
            )
        return all_events

    baseline = get_baseline(device_mac)
    if not baseline:
        return all_events

    all_events.extend(_check_volume_spike(current_flow, baseline, device_mac))
    all_events.extend(_check_connection_spike(current_flow, baseline, device_mac))
    all_events.extend(_check_unusual_destinations(current_flow, baseline, device_mac))

    if all_events:
        logger.info(
            "Anomaly checks for %s: %d events/alerts generated",
            device_mac, len(all_events),
        )

    return all_events

def _is_private_ipv4(ip: str | None) -> bool:
    """Return True for RFC1918 IPv4 addresses. Keeps the first scan rule LAN-focused."""
    if not ip or ":" in ip:
        return False

    if ip.startswith("10.") or ip.startswith("192.168."):
        return True

    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) < 2:
            return False
        try:
            second = int(parts[1])
            return 16 <= second <= 31
        except ValueError:
            return False

    return False


def _is_benign_gateway_service_mix(top_dest: str | None, top_ports: list[int]) -> bool:
    """
    Suppress a narrow false-positive pattern:
    gateway-targeted local service chatter that mixes SSH with common
    local gateway/discovery traffic.

    This is intentionally conservative so it does not broadly disable
    local probe detection.
    """
    if not top_dest:
        return False

    if top_dest != GATEWAY_IP:
        return False

    try:
        port_set = {int(p) for p in top_ports}
    except Exception:
        return False

    benign_ports = {22, 53, 1900, 5351, 5353}

    return 22 in port_set and port_set.issubset(benign_ports)


def _confidence_from_probe(
    max_ports_single_dest: int,
    max_connections_single_dest: int,
    unique_ports: int,
    total_connections: int,
) -> float:
    """
    Conservative confidence model for scan/probe behavior.

    We keep this bounded because conntrack only shows part of the activity,
    so this should be treated as a strong advisory signal, not automatic truth.
    """
    score = 0.68
    score += max(0, max_ports_single_dest - 3) * 0.03
    score += max(0, max_connections_single_dest - 8) * 0.015
    score += max(0, unique_ports - 6) * 0.01
    score += max(0, total_connections - 40) * 0.002
    return min(score, 0.85)


def _check_scan_probe(flow: dict, mac: str) -> list[dict]:
    """
    Detect one-target multi-port probing from enriched flow summary fields.

    This is intentionally medium severity and advisory-first:
      - It should create a meaningful signal
      - It should route into the decision engine
      - It should not become an aggressive one-shot quarantine trigger
    """
    events = []

    top_dest = flow.get("top_port_fanout_dest")
    max_ports_single_dest = int(flow.get("max_ports_single_dest", 0) or 0)
    max_connections_single_dest = int(flow.get("max_connections_single_dest", 0) or 0)
    unique_ports = int(flow.get("unique_ports", len(flow.get("ports", []))) or 0)
    total_connections = int(flow.get("connections", 0) or 0)
    top_ports = list(flow.get("top_port_fanout_ports", []))
    scan_candidates = list(flow.get("scan_candidates", []))

    # First-pass conservative thresholds tuned to your current adversary validation.
    # We require:
    #   - a local/private destination
    #   - at least some multi-port fanout against that one target
    #   - elevated total device activity
    #   - broader port diversity than normal background alone
    if not top_dest:
        return events

    if not _is_private_ipv4(top_dest):
        return events

    if _is_benign_gateway_service_mix(top_dest, top_ports):
        logger.debug(
            "Skipping scan probe for %s due to benign gateway service mix: dest=%s ports=%s",
            mac, top_dest, top_ports,
        )
        return events

    if max_ports_single_dest < 3:
        return events

    if max_connections_single_dest < 8:
        return events

    if total_connections < 15:
        return events

    severity = "medium"
    enforcement = _enforcement_for_severity(severity)

    event = build_anomaly_detected(mac, {
        "anomaly_type": "scan_probe",
        "metric": "port_fanout_single_dest",
        "current_value": max_ports_single_dest,
        "top_dest_ip": top_dest,
        "top_dest_connections": max_connections_single_dest,
        "top_dest_ports": top_ports,
        "device_total_connections": total_connections,
        "device_unique_ports": unique_ports,
        "scan_candidates": scan_candidates,
    })
    enqueue_and_dispatch(event)
    events.append(event)

    if _should_alert(severity, mac, "scan_probe"):
        _route_to_detection(
            mac,
            severity,
            (
                f"scan_probe top_dest={top_dest} "
                f"ports={max_ports_single_dest} "
                f"connections={max_connections_single_dest} "
                f"device_connections={total_connections}"
            ),
        )

        alert = build_alert(
            device_id=mac,
            severity=severity,
            title="Possible local service probing detected",
            explanation=(
                f"The device {mac} ({flow.get('ip_address', 'unknown IP')}) showed "
                f"concentrated connection activity against {top_dest}, with "
                f"{max_connections_single_dest} tracked connections across "
                f"{max_ports_single_dest} visible destination ports during the same interval. "
                f"This pattern can indicate service enumeration or port probing against a local target."
            ),
            evidence={
                "source_module": "anomaly",
                "details": {
                    "anomaly_type": "scan_probe",
                    "device_ip": flow.get("ip_address"),
                    "top_port_fanout_dest": top_dest,
                    "max_ports_single_dest": max_ports_single_dest,
                    "max_connections_single_dest": max_connections_single_dest,
                    "unique_ports": unique_ports,
                    "connections": total_connections,
                    "top_port_fanout_ports": top_ports,
                    "scan_candidates": scan_candidates,
                },
            },
            recommended_action=(
                f"Investigate whether the device at {flow.get('ip_address', mac)} "
                f"was intentionally probing services on {top_dest}. Review local service exposure, "
                f"correlate with IDS or firewall evidence, and verify whether this device should be "
                f"making repeated multi-port requests to that target."
            ),
            confidence=_confidence_from_probe(
                max_ports_single_dest=max_ports_single_dest,
                max_connections_single_dest=max_connections_single_dest,
                unique_ports=unique_ports,
                total_connections=total_connections,
            ),
            related_event_ids=[event["id"]],
        )
        if enforcement:
            alert["recommended_enforcement"] = enforcement

        enqueue_and_dispatch(alert)
        events.append(alert)

    logger.info(
        "Scan probe detected for %s: top_dest=%s ports=%d conns=%d total_conns=%d unique_ports=%d",
        mac,
        top_dest,
        max_ports_single_dest,
        max_connections_single_dest,
        total_connections,
        unique_ports,
    )

    return events
