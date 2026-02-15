"""
Bastión Xólot — Behavioral Baseline Module (Phase 3 — STUB)

STATUS: Not yet implemented. Scheduled for Phase 3 (Feb 17 – Mar 1).

This module will establish a "normal behavior model" for each device
on the network by observing traffic metadata over time.  The baseline
feeds into the anomaly detector (anomaly.py).

Planned baseline dimensions per device:
  - Typical destinations (IPs / domains)
  - Usual ports and protocols
  - Normal connection frequency (connections per hour)
  - Expected byte volumes (daily average ± stddev)
  - Active hours (when the device normally communicates)

Learning strategy:
  - Minimum observation period: BASELINE_LEARNING_HOURS (config.py)
  - Rolling window: last 7 days of flow summaries
  - Percentile-based thresholds (e.g., 95th percentile for spikes)
  - Baseline updates incrementally as new data arrives

Storage:
  - Baseline profiles stored in local SQLite (agent-side)
  - Summaries forwarded to backend for correlation
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def update_baseline(device_mac: str, flow_summary: dict) -> None:
    """
    Incorporate a new flow summary into a device's baseline model.

    Phase 3 implementation will:
      1. Load existing baseline from storage
      2. Update running statistics (mean, stddev, percentiles)
      3. Save updated baseline
      4. Mark baseline as "learning" or "stable"
    """
    logger.debug("baseline.update_baseline(%s) — not yet implemented (Phase 3)", device_mac)


def get_baseline(device_mac: str) -> Optional[dict]:
    """
    Retrieve the current baseline profile for a device.

    Returns None if the device has no established baseline
    (still in learning period).
    """
    logger.debug("baseline.get_baseline(%s) — not yet implemented (Phase 3)", device_mac)
    return None


def is_baseline_stable(device_mac: str) -> bool:
    """
    Check whether a device's baseline has enough data to be
    considered stable (past the learning period).
    """
    logger.debug("baseline.is_baseline_stable(%s) — not yet implemented (Phase 3)", device_mac)
    return False
