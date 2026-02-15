"""
Bastión Xólot — Anomaly Detection Module (Phase 3 — STUB)

STATUS: Not yet implemented. Scheduled for Phase 3 (Feb 17 – Mar 1).

This module will compare current device behavior against established
baselines to detect deviations that may indicate compromise,
misconfiguration, or unauthorized activity.

Planned anomaly types:
  - Traffic volume spike (bytes or connections significantly above baseline)
  - Unusual destination (device contacts IP/domain never seen before)
  - Excessive connection attempts (possible scanning or brute-force)
  - Protocol anomaly (device using unexpected ports/protocols)
  - Time-of-day anomaly (activity outside normal operating hours)

Each detected anomaly generates:
  1. An `anomaly_detected` event (machine-readable)
  2. An alert with plain-English explanation (user-readable)

Severity assignment:
  - low:    mild deviation, first occurrence
  - medium: significant spike or repeated unusual behavior
  - high:   known-bad pattern or severe deviation from baseline
"""

import logging

logger = logging.getLogger(__name__)


def check_for_anomalies(device_mac: str, current_flow: dict) -> list[dict]:
    """
    Compare a device's current flow summary against its baseline.

    Phase 3 implementation will:
      1. Load baseline for the device
      2. Compare each metric against threshold
      3. Generate anomaly_detected events for deviations
      4. Generate alerts with plain-English explanations
      5. Return list of events and alerts

    Returns empty list until implemented.
    """
    logger.debug("anomaly.check_for_anomalies(%s) — not yet implemented (Phase 3)", device_mac)
    return []
