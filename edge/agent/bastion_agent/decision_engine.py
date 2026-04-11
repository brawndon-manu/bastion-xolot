from __future__ import annotations

from typing import Dict, Any


SCORE_MONITOR_MAX = 39
SCORE_ALERT_MAX = 69
SCORE_SOFT_MAX = 89

SIGNAL_SCORES = {
    ("anomaly", "medium"): 20,
    ("anomaly", "high"): 45,
    ("suricata", "low"): 5,
    ("suricata", "medium"): 15,
    ("suricata", "high"): 30,
}


def score_event(event: Dict[str, Any]) -> int:
    """
    Return the base score contribution for a normalized event.
    """
    source = event.get("source", "unknown")
    severity = event.get("severity", "low").lower()

    return SIGNAL_SCORES.get((source, severity), 0)


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