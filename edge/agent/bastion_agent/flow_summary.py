"""
Bastión Xólot — Flow Summary Module (Phase 3 — STUB)

STATUS: Not yet implemented. Scheduled for Phase 3 (Feb 17 – Mar 1).

This module will collect network metadata (NOT packet payloads) to
build per-device traffic summaries used by the baseline and anomaly
detection modules.

Planned data sources:
  - conntrack (connection tracking table) for active connections
  - ss (socket statistics) for connection counts
  - nftables byte/packet counters for volume metrics
  - /proc/net/nf_conntrack for destination tracking

Metadata collected per device per interval:
  - Unique destination IPs / domains
  - Ports and protocols used
  - Connection counts (new connections per interval)
  - Byte volumes (inbound + outbound)
  - DNS query frequency

NOTE: Flow summary collection requires nftables rules to be in place.
      That configuration is owned by the Systems Architect
      (infra/scripts/setup_firewall.sh).
"""

import logging

logger = logging.getLogger(__name__)


def collect_flow_summaries() -> list[dict]:
    """
    Collect per-device traffic metadata summaries.

    Phase 3 implementation will:
      1. Read conntrack table for active connections
      2. Aggregate by source MAC / IP
      3. Build flow_summary events with connection counts,
         byte volumes, and destination lists
      4. Return list of flow_summary event dicts

    Returns empty list until implemented.
    """
    logger.debug("flow_summary.collect_flow_summaries() — not yet implemented (Phase 3)")
    return []
