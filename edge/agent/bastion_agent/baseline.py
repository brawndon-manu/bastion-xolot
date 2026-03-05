"""
Bastión Xólot — Behavioral Baseline Module (Phase 3)

Establishes a "normal behavior model" for each device on the network
by observing traffic metadata over time.  The baseline feeds into
the anomaly detector (anomaly.py).

Algorithm: Welford's online algorithm for computing running mean
and variance in a single pass, without storing all historical data.
This is ideal for an edge device with limited storage.

Baseline dimensions per device:
  - connection_count  (connections per summary interval)
  - bytes_out         (outbound bytes per interval)
  - unique_dests      (unique destination count per interval)
  - known_destinations (set of all previously seen destination IPs)
  - active_hours      (hours of day when device communicates)

Learning → Stable transition:
  A baseline is marked "stable" once sample_count reaches the
  threshold derived from BASELINE_LEARNING_HOURS / FLOW_SUMMARY_INTERVAL.

Satisfies Requirement 1.6:
  "The system shall establish a baseline of normal behavior for each device."
"""

import json
import math
import logging
from datetime import datetime, timezone

from bastion_agent.config import BASELINE_LEARNING_HOURS, FLOW_SUMMARY_INTERVAL
from bastion_agent.storage import get_baseline as _db_get_baseline, upsert_baseline
from bastion_agent.utils import utcnow_iso

logger = logging.getLogger(__name__)

# Minimum samples before baseline is considered stable
# e.g., 24 hours / 60-second interval = 1440 samples
_MIN_SAMPLES = max(1, (BASELINE_LEARNING_HOURS * 3600) // max(FLOW_SUMMARY_INTERVAL, 1))


def _welford_update(
    count: int, mean: float, m2: float, new_value: float
) -> tuple[int, float, float]:
    """
    Welford's online algorithm: update running mean and M2.

    M2 is the sum of squared deviations from the mean.
    Variance = M2 / count (population) or M2 / (count - 1) (sample).
    """
    count += 1
    delta = new_value - mean
    mean += delta / count
    delta2 = new_value - mean
    m2 += delta * delta2
    return count, mean, m2


def _stddev_from_m2(count: int, m2: float) -> float:
    """Compute standard deviation from Welford's M2 accumulator."""
    if count < 2:
        return 0.0
    return math.sqrt(m2 / count)


def update_baseline(device_mac: str, flow_summary: dict) -> dict:
    """
    Incorporate a new flow summary into a device's baseline model.

    Uses Welford's online algorithm to update mean and M2 for each
    metric without storing all historical data points.

    Returns the updated baseline dict.
    """
    existing = _db_get_baseline(device_mac)
    now = utcnow_iso()
    current_hour = datetime.now(timezone.utc).hour

    if existing:
        count = existing["sample_count"]
        conn_mean = existing["connections_mean"]
        conn_m2 = existing["connections_m2"]
        bytes_mean = existing["bytes_out_mean"]
        bytes_m2 = existing["bytes_out_m2"]
        dests_mean = existing["unique_dests_mean"]
        dests_m2 = existing["unique_dests_m2"]

        known_dests: list[str] = json.loads(existing["known_destinations"] or "[]")
        active_hrs: list[int] = json.loads(existing["active_hours"] or "[]")
        first_sample = existing["first_sample"]
    else:
        count = 0
        conn_mean = conn_m2 = 0.0
        bytes_mean = bytes_m2 = 0.0
        dests_mean = dests_m2 = 0.0
        known_dests = []
        active_hrs = []
        first_sample = now

    # Update running statistics with Welford's algorithm
    count, conn_mean, conn_m2 = _welford_update(
        count, conn_mean, conn_m2, flow_summary["connections"]
    )
    _, bytes_mean, bytes_m2 = _welford_update(
        count - 1, bytes_mean, bytes_m2, flow_summary["bytes_out"]
    )
    _, dests_mean, dests_m2 = _welford_update(
        count - 1, dests_mean, dests_m2, flow_summary["unique_dests"]
    )

    # Merge new destinations into known set (cap at 500 to bound memory)
    new_dests = flow_summary.get("destinations", [])
    dest_set = set(known_dests)
    dest_set.update(new_dests)
    if len(dest_set) > 500:
        dest_set = set(sorted(dest_set)[:500])
    known_dests = sorted(dest_set)

    # Track active hours
    if current_hour not in active_hrs:
        active_hrs.append(current_hour)
        active_hrs.sort()

    # Determine if baseline is stable
    status = "stable" if count >= _MIN_SAMPLES else "learning"

    baseline_data = {
        "connections_mean": conn_mean,
        "connections_m2": conn_m2,
        "bytes_out_mean": bytes_mean,
        "bytes_out_m2": bytes_m2,
        "unique_dests_mean": dests_mean,
        "unique_dests_m2": dests_m2,
        "known_destinations": json.dumps(known_dests),
        "active_hours": json.dumps(active_hrs),
        "sample_count": count,
        "first_sample": first_sample,
        "last_sample": now,
        "status": status,
    }

    upsert_baseline(device_mac, baseline_data)

    if status == "stable" and (existing is None or existing.get("status") == "learning"):
        logger.info(
            "Baseline for %s is now stable (%d samples)",
            device_mac, count,
        )

    return baseline_data


def get_baseline(device_mac: str) -> dict | None:
    """
    Retrieve the current baseline profile for a device.

    Returns None if the device has no baseline data.
    Enriches the raw DB record with computed stddev values
    for use by the anomaly detector.
    """
    raw = _db_get_baseline(device_mac)
    if not raw:
        return None

    count = raw["sample_count"]
    return {
        **raw,
        "connections_stddev": _stddev_from_m2(count, raw["connections_m2"]),
        "bytes_out_stddev": _stddev_from_m2(count, raw["bytes_out_m2"]),
        "unique_dests_stddev": _stddev_from_m2(count, raw["unique_dests_m2"]),
        "known_destinations_list": json.loads(raw["known_destinations"] or "[]"),
        "active_hours_list": json.loads(raw["active_hours"] or "[]"),
    }


def is_baseline_stable(device_mac: str) -> bool:
    """Check whether a device has accumulated enough data for reliable anomaly detection."""
    raw = _db_get_baseline(device_mac)
    if not raw:
        return False
    return raw["status"] == "stable"
