from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from typing import Deque, Dict, Any

from bastion_agent.utils import utcnow


SCORE_MONITOR_MAX = 39
SCORE_ALERT_MAX = 69
SCORE_SOFT_MAX = 109

SIGNAL_SCORES = {
    ("anomaly", "medium"): 20,
    ("anomaly", "high"): 45,
    ("suricata", "low"): 5,
    ("suricata", "medium"): 15,
    ("suricata", "high"): 30,
}

REPEAT_BONUS = 15
CORROBORATION_BONUS = 20
WINDOW_SECONDS = 300  # 5 minutes

# device_id -> deque of recent signal records
_SIGNAL_HISTORY: Dict[str, Deque[dict]] = defaultdict(deque)


def _prune_old(device_id: str) -> None:
    cutoff = utcnow() - timedelta(seconds=WINDOW_SECONDS)
    history = _SIGNAL_HISTORY[device_id]

    while history and history[0]["ts"] < cutoff:
        history.popleft()


def score_event(event: Dict[str, Any]) -> int:
    """
    Return the base score contribution for a normalized event.
    """
    source = event.get("source", "unknown")
    severity = event.get("severity", "low").lower()

    return SIGNAL_SCORES.get((source, severity), 0)


def record_signal(event: Dict[str, Any]) -> int:
    """
    Record a normalized event for a device and return the accumulated score
    within the current decision window.
    """
    device_id = str(event.get("device_id", "")).lower()
    if not device_id:
        raise ValueError("event missing device_id")

    _prune_old(device_id)

    base_score = score_event(event)
    source = event.get("source", "unknown")
    severity = event.get("severity", "low").lower()

    history = _SIGNAL_HISTORY[device_id]

    repeat = any(
        h["source"] == source and h["severity"] == severity
        for h in history
    )

    corroborated = any(
        h["source"] != source
        for h in history
    )

    history.append({
        "ts": utcnow(),
        "source": source,
        "severity": severity,
        "base_score": base_score,
    })

    total = sum(h["base_score"] for h in history)

    if repeat:
        total += REPEAT_BONUS

    if corroborated:
        total += CORROBORATION_BONUS

    return total


def action_tier(score: int) -> str:
    """
    Map score to an action tier.
    """
    if score <= SCORE_MONITOR_MAX:
        return "monitor"
    if score <= SCORE_ALERT_MAX:
        return "alert"
    if score <= SCORE_SOFT_MAX:
        return "soft_quarantine"
    return "hard_quarantine"