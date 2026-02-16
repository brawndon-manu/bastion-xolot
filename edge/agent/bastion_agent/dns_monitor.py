"""
Bastión Xólot — DNS Sinkhole Log Monitor (Phase 2)

Watches the DNS resolver log file (dnsmasq) for blocked queries
and generates `dns_blocked` events + alerts.

Supported DNS log formats
─────────────────────────
This module is designed for **dnsmasq** running on the Raspberry Pi,
which is the DNS resolver the Systems Architect will configure via
`infra/scripts/setup_dns_sinkhole.sh`.

Dnsmasq log line formats (with --log-queries enabled):

  Standard query:
    Feb 14 10:30:45 dnsmasq[1234]: query[A] example.com from 192.168.1.100

  Blocked via address=/domain/0.0.0.0 (sinkhole):
    Feb 14 10:30:45 dnsmasq[1234]: config example.com is 0.0.0.0

  Blocked via address=/domain/ (NXDOMAIN):
    Feb 14 10:30:45 dnsmasq[1234]: config example.com is NXDOMAIN

  Normal reply:
    Feb 14 10:30:45 dnsmasq[1234]: reply example.com is 93.184.216.34

Flow data sources identified (Phase 0 documentation)
────────────────────────────────────────────────────
  - DNS queries/blocks:  /var/log/dnsmasq.log  (this module)
  - Connection metadata:  conntrack / ss        (Phase 3 flow_summary.py)
  - Traffic counters:     nftables counters     (Phase 3 flow_summary.py)

Prerequisites (owned by Systems Architect):
  - dnsmasq must be installed and configured as DNS resolver
  - --log-queries must be enabled in dnsmasq.conf
  - Blocklist must be loaded into dnsmasq (address=/ entries)
  - DNS_LOG_PATH must point to the correct log file
"""

import re
import os
import time
import logging
from pathlib import Path
from typing import Optional
from datetime import datetime

from bastion_agent.config import DNS_LOG_PATH, DNS_POLL_INTERVAL
from bastion_agent.events import (
    build_dns_blocked,
    build_alert,
    enqueue_and_dispatch,
)
from bastion_agent.storage import record_dns_block

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# Log line patterns (dnsmasq with --log-queries)
# ─────────────────────────────────────────────

# Matches: "query[A] malware.example.com from 192.168.1.100"
_QUERY_RE = re.compile(
    r"query\[(?P<qtype>[A-Z]+)\]\s+"
    r"(?P<domain>\S+)\s+"
    r"from\s+(?P<client_ip>\S+)"
)

# Matches: "config malware.example.com is 0.0.0.0"
# or:      "config malware.example.com is NXDOMAIN"
# or:      "config malware.example.com is ::"
_BLOCKED_RE = re.compile(
    r"config\s+(?P<domain>\S+)\s+is\s+(?P<answer>\S+)"
)

# Sinkhole answers that indicate a blocked domain
_SINKHOLE_ANSWERS = {"0.0.0.0", "::", "NXDOMAIN", "127.0.0.1"}

# Matches the syslog timestamp + process prefix
# Example: "Feb 14 10:30:45 raspberrypi dnsmasq[1234]: "
_SYSLOG_PREFIX_RE = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+"
    r"(?:\S+\s+)?"  # hostname (optional)
    r"dnsmasq\[\d+\]:\s+"
)


class DnsMonitor:
    """
    Monitors the dnsmasq log file for DNS queries and blocked domains.

    Usage:
        monitor = DnsMonitor("/var/log/dnsmasq.log")
        for event in monitor.poll():
            # process event
    """

    def __init__(self, log_path: str | None = None):
        self.log_path = Path(log_path or DNS_LOG_PATH)
        self._file_pos: int = 0
        self._inode: int | None = None

        # Track recent queries to correlate query → block pairs
        # Maps domain → most recent client_ip that queried it
        self._recent_queries: dict[str, str] = {}

        # Initialize file position to end-of-file (only process new entries)
        self._seek_to_end()

    def _seek_to_end(self) -> None:
        """Position the reader at the end of the current log file."""
        if self.log_path.exists():
            stat = self.log_path.stat()
            self._file_pos = stat.st_size
            self._inode = stat.st_ino
            logger.info(
                "DNS monitor initialized — watching %s (pos=%d)",
                self.log_path, self._file_pos,
            )
        else:
            logger.warning(
                "DNS log file not found: %s — will retry on next poll. "
                "The Systems Architect must configure dnsmasq and enable "
                "--log-queries for DNS monitoring to work.",
                self.log_path,
            )
            self._file_pos = 0
            self._inode = None

    def _check_log_rotation(self) -> bool:
        """
        Detect if the log file has been rotated (new inode or smaller size).
        Returns True if rotation was detected and position was reset.
        """
        if not self.log_path.exists():
            return False

        stat = self.log_path.stat()
        if self._inode is not None and stat.st_ino != self._inode:
            logger.info("DNS log file rotated (inode changed) — resetting position")
            self._file_pos = 0
            self._inode = stat.st_ino
            return True

        if stat.st_size < self._file_pos:
            logger.info("DNS log file truncated — resetting position")
            self._file_pos = 0
            return True

        return False

    def _read_new_lines(self) -> list[str]:
        """Read any new lines appended since last check."""
        if not self.log_path.exists():
            return []

        self._check_log_rotation()

        try:
            with open(self.log_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self._file_pos)
                new_data = f.read()
                self._file_pos = f.tell()
        except (OSError, IOError) as exc:
            logger.warning("Error reading DNS log: %s", exc)
            return []

        if not new_data:
            return []

        return new_data.strip().splitlines()

    def _parse_line(self, line: str) -> Optional[dict]:
        """
        Parse a single dnsmasq log line.

        Returns an event dict if the line is relevant, None otherwise.
        """
        # Strip syslog prefix to get dnsmasq message body
        prefix_match = _SYSLOG_PREFIX_RE.match(line)
        if not prefix_match:
            return None

        timestamp_str = prefix_match.group("timestamp")
        body = line[prefix_match.end():]

        # ── Check for a blocked response ──
        blocked_match = _BLOCKED_RE.match(body)
        if blocked_match:
            domain = blocked_match.group("domain")
            answer = blocked_match.group("answer")

            if answer in _SINKHOLE_ANSWERS:
                # Look up which client queried this domain
                client_ip = self._recent_queries.pop(domain, "unknown")

                return {
                    "type": "blocked",
                    "domain": domain,
                    "client_ip": client_ip,
                    "answer": answer,
                    "timestamp": timestamp_str,
                }

        # ── Check for a query ──
        query_match = _QUERY_RE.search(body)
        if query_match:
            domain = query_match.group("domain")
            client_ip = query_match.group("client_ip")
            qtype = query_match.group("qtype")

            # Cache for block correlation
            self._recent_queries[domain] = client_ip

            # Keep cache bounded
            if len(self._recent_queries) > 5000:
                # Evict oldest half
                keys = list(self._recent_queries.keys())
                for k in keys[:2500]:
                    del self._recent_queries[k]

            return {
                "type": "query",
                "domain": domain,
                "client_ip": client_ip,
                "query_type": qtype,
                "timestamp": timestamp_str,
            }

        return None

    def poll(self) -> list[dict]:
        """
        Check for new DNS log entries and generate events.

        Returns a list of event dicts (dns_blocked events and alerts).
        Called periodically by the agent main loop.
        """
        lines = self._read_new_lines()
        if not lines:
            return []

        events: list[dict] = []
        block_count = 0

        for line in lines:
            parsed = self._parse_line(line)
            if parsed is None:
                continue

            if parsed["type"] == "blocked":
                block_count += 1

                # Record in local storage
                record_dns_block(
                    domain=parsed["domain"],
                    client_ip=parsed["client_ip"],
                    timestamp=parsed["timestamp"],
                )

                # Build dns_blocked event
                event = build_dns_blocked(
                    domain=parsed["domain"],
                    client_ip=parsed["client_ip"],
                    block_reason="sinkhole",
                )
                enqueue_and_dispatch(event)
                events.append(event)

                # Generate alert for blocked domain
                alert = build_alert(
                    device_id=parsed["client_ip"],  # use IP until MAC correlation exists
                    severity="medium",
                    title=f"Blocked connection to {parsed['domain']}",
                    explanation=(
                        f"A device at {parsed['client_ip']} attempted to connect to "
                        f"{parsed['domain']}, which is on the blocklist of known "
                        f"malicious or unwanted domains. The connection was blocked "
                        f"by the DNS sinkhole."
                    ),
                    evidence={
                        "source_module": "dns_monitor",
                        "blocked_domain": parsed["domain"],
                        "details": {
                            "client_ip": parsed["client_ip"],
                            "sinkhole_answer": parsed["answer"],
                            "log_timestamp": parsed["timestamp"],
                        },
                    },
                    recommended_action=(
                        f"Check the device at {parsed['client_ip']} for malware or "
                        f"unwanted software. If this is a false positive, you can "
                        f"whitelist the domain from the app."
                    ),
                    confidence=0.9,
                    related_event_ids=[event["id"]],
                )
                enqueue_and_dispatch(alert)
                events.append(alert)

                logger.info(
                    "DNS block detected: %s → %s (from %s)",
                    parsed["client_ip"], parsed["domain"], parsed["answer"],
                )

        if block_count:
            logger.info("DNS poll: %d new lines, %d blocks detected", len(lines), block_count)

        return events
