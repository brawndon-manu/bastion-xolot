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
    Parse Suricata EVE JSON log and return Bastión Xólot events.

    Enhancement implementation would:
      1. Tail the EVE JSON log file
      2. Parse alert-type entries
      3. Map Suricata severity/category to Bastión severity
      4. Build anomaly_detected or dns_blocked events
      5. Correlate with existing device inventory

    Returns empty list until implemented.
    """
    logger.debug("suricata_adapter.parse_eve_log() — not yet implemented (enhancement)")
    return []
