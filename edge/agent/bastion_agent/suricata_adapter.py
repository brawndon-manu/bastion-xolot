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
    - Reads alert events from file
    - Parses Suricata alert events
    - Returns normalized Bastion events
    """

    import json

    events = []

    try:
        with open(log_path, "r") as f:
            for line in f:
                if not line.strip():
                    continue

                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    logger.warning("Skipping invalid JSON line in EVE log")
                    continue

                # Only handle Suricata alert events
                if data.get("event_type") != "alert":
                    continue

                alert = data.get("alert", {})

                if data.get("src_mac"):
                    device_id = data.get("src_mac")
                    device_id_type = "mac"
                elif data.get("src_ip"):
                    device_id = data.get("src_ip")
                    device_id_type = "ip"
                else:
                    continue

                # Map Suricata severity to Bastion severity
                sev_map = {
                    1: "high",
                    2: "medium",
                    3: "low"
                }

                severity = sev_map.get(alert.get("severity"), "low")

                event = {
                    "device_id": device_id,
                    "device_id_type": device_id_type,
                    "severity": severity,
                    "reason": alert.get("signature", "suricata alert")
                }

                events.append(event)

    except FileNotFoundError:
        logger.warning(f"EVE log not found: {log_path}")
    except Exception as e:
        logger.error(f"Failed to parse EVE log: {e}")

    return events