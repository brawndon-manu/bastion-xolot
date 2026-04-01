"""
Bastión Xólot — Suricata IDS Adapter (OPTIONAL Enhancement — STUB)

STATUS: Not yet implemented. This is an optional enhancement that can
be added if Suricata is deployed alongside the gateway.

This module would read Suricata's EVE JSON log output and convert
IDS alerts into Bastión Xólot events for correlation with the
metadata-based detection pipeline.

Suricata EVE log format:
  - JSON-lines format (one JSON object per line)
  - Located at /var/log/suricata/eve.json by default
  - Event types: alert, dns, http, flow, stats, etc.

Integration points:
  - Suricata alerts → bastion alerts (severity mapping)
  - Suricata DNS events → enrichment for dns_monitor
  - Suricata flow events → enrichment for flow_summary

NOTE: Suricata installation and configuration is owned by the
      Systems Architect (infra/scripts/setup_suricata.sh).
"""

import logging

logger = logging.getLogger(__name__)


def parse_eve_log(log_path: str = "/var/log/suricata/eve.json") -> list[dict]:
    """
    Minimal implementation:
    - Reads ONE line from file
    - Parses alert events
    - Returns normalized Bastion event
    """

    import json

    events = []

    try:
        with open(log_path, "r") as f:
            line = f.readline()

            if not line:
                return []

            data = json.loads(line)

            # Only handle Suricata alert events
            if data.get("event_type") != "alert":
                return []

            mac = data.get("src_mac")
            alert = data.get("alert", {})

            # Map Suricata severity → Bastion severity
            sev_map = {
                1: "high",
                2: "medium",
                3: "low"
            }

            severity = sev_map.get(alert.get("severity"), "low")

            event = {
                "mac": mac,
                "severity": severity,
                "reason": alert.get("signature", "suricata alert")
            }

            events.append(event)

    except Exception as e:
        logger.error(f"Failed to parse EVE log: {e}")

    return events