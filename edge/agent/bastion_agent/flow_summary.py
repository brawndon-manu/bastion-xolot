"""
Bastión Xólot — Flow Summary Module (Phase 3)

Collects network metadata (NOT packet payloads) to build per-device
traffic summaries.  These summaries feed into the baseline and
anomaly detection modules.

Data source: Linux conntrack (connection tracking table)
  - conntrack tracks every connection flowing through the Pi gateway
  - Provides: protocol, src/dst IP, src/dst port, packet count, byte count
  - Available at /proc/net/nf_conntrack or via `conntrack -L`

Metadata collected per device per interval:
  - Unique destination IPs
  - Ports and protocols used
  - Total connection count
  - Byte volumes (outbound + inbound)

Satisfies Requirement 1.5 (Metadata-Based Traffic Monitoring):
  "The system shall collect network metadata only, not packet payloads."

Prerequisites (owned by Systems Architect):
  - nf_conntrack kernel module must be loaded
  - conntrack-tools package should be installed
  - nftables rules must be in place for connection tracking
"""

import re
import subprocess
import json
import logging
from collections import defaultdict
from typing import Optional

from bastion_agent.config import FLOW_SUMMARY_INTERVAL
from bastion_agent.events import build_flow_summary, enqueue_and_dispatch
from bastion_agent.storage import (
    ip_to_mac,
    get_all_device_ips,
    store_flow_summary,
)

logger = logging.getLogger(__name__)

# Regex for parsing conntrack entries (both `conntrack -L` and /proc/net/nf_conntrack)
# Example line:
#   ipv4  2 tcp  6 299 ESTABLISHED src=192.168.50.100 dst=142.250.80.46
#   sport=52340 dport=443 packets=15 bytes=2340 src=142.250.80.46
#   dst=192.168.50.1 sport=443 dport=52340 packets=12 bytes=8765 [ASSURED]
_KV_RE = re.compile(r"(\w+)=(\S+)")
_PROTO_RE = re.compile(r"\b(tcp|udp|icmp|sctp)\b", re.IGNORECASE)


def _parse_conntrack_line(line: str) -> Optional[dict]:
    """
    Parse a single conntrack entry into a structured dict.

    Returns None for unparseable or irrelevant lines.
    Each conntrack line has two direction halves (original + reply).
    We extract the original direction (first src/dst pair).
    """
    pairs = _KV_RE.findall(line)
    if len(pairs) < 6:
        return None

    proto_match = _PROTO_RE.search(line)
    protocol = proto_match.group(1).lower() if proto_match else "unknown"

    # conntrack lines have duplicate keys (original + reply direction)
    # The first occurrence of src/dst is the original direction
    fields: dict[str, list[str]] = defaultdict(list)
    for key, val in pairs:
        fields[key].append(val)

    if "src" not in fields or "dst" not in fields:
        return None

    try:
        return {
            "protocol": protocol,
            "src_ip": fields["src"][0],
            "dst_ip": fields["dst"][0],
            "src_port": int(fields["sport"][0]) if "sport" in fields else 0,
            "dst_port": int(fields["dport"][0]) if "dport" in fields else 0,
            "packets_out": int(fields["packets"][0]) if "packets" in fields else 0,
            "bytes_out": int(fields["bytes"][0]) if "bytes" in fields else 0,
            "packets_in": int(fields["packets"][1]) if len(fields.get("packets", [])) > 1 else 0,
            "bytes_in": int(fields["bytes"][1]) if len(fields.get("bytes", [])) > 1 else 0,
        }
    except (IndexError, ValueError):
        return None


def _read_conntrack() -> list[dict]:
    """
    Read the conntrack table. Tries `conntrack -L` first,
    falls back to /proc/net/nf_conntrack.
    """
    # Try conntrack command
    try:
        result = subprocess.run(
            ["conntrack", "-L", "-f", "ipv4", "-o", "extended"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip():
            lines = result.stdout.strip().splitlines()
            entries = []
            for line in lines:
                parsed = _parse_conntrack_line(line)
                if parsed:
                    entries.append(parsed)
            return entries
    except FileNotFoundError:
        logger.debug("conntrack command not found, trying /proc/net/nf_conntrack")
    except subprocess.TimeoutExpired:
        logger.warning("conntrack -L timed out")

    # Fallback: read /proc/net/nf_conntrack directly
    try:
        with open("/proc/net/nf_conntrack", "r") as f:
            lines = f.readlines()
        entries = []
        for line in lines:
            parsed = _parse_conntrack_line(line)
            if parsed:
                entries.append(parsed)
        return entries
    except FileNotFoundError:
        logger.warning(
            "Neither conntrack nor /proc/net/nf_conntrack available. "
            "The Systems Architect must ensure nf_conntrack is loaded."
        )
        return []
    except PermissionError:
        logger.warning("/proc/net/nf_conntrack not readable — agent may need root")
        return []


def _aggregate_by_device(
    connections: list[dict], lan_ips: set[str]
) -> dict[str, dict]:
    """
    Group conntrack entries by source LAN device and compute per-device summaries.

    Only includes connections originating from known LAN devices
    (identified by source IP being in the known_devices table).
    """
    device_data: dict[str, dict] = defaultdict(lambda: {
        "connections": 0,
        "bytes_out": 0,
        "bytes_in": 0,
        "destinations": set(),
        "ports": set(),
        "protocols": set(),
    })

    for conn in connections:
        src_ip = conn["src_ip"]

        # Only track outbound connections from LAN devices
        if src_ip not in lan_ips:
            continue

        d = device_data[src_ip]
        d["connections"] += 1
        d["bytes_out"] += conn["bytes_out"]
        d["bytes_in"] += conn["bytes_in"]
        d["destinations"].add(conn["dst_ip"])
        if conn["dst_port"]:
            d["ports"].add(conn["dst_port"])
        d["protocols"].add(conn["protocol"])

    return dict(device_data)


def collect_flow_summaries() -> list[dict]:
    """
    Collect per-device traffic metadata summaries from conntrack.

    For each LAN device with active connections:
      1. Reads conntrack table
      2. Aggregates by source device IP
      3. Maps IP → MAC using known_devices
      4. Stores summary in local SQLite
      5. Builds and enqueues flow_summary events

    Returns list of flow summary dicts (one per device with traffic).
    """
    connections = _read_conntrack()
    if not connections:
        logger.debug("No conntrack entries found")
        return []

    lan_ips = get_all_device_ips()
    if not lan_ips:
        logger.debug("No known devices yet — skipping flow summary")
        return []

    device_summaries = _aggregate_by_device(connections, lan_ips)
    results: list[dict] = []

    for ip, data in device_summaries.items():
        mac = ip_to_mac(ip)
        if not mac:
            continue

        summary = {
            "mac_address": mac,
            "ip_address": ip,
            "connections": data["connections"],
            "bytes_out": data["bytes_out"],
            "bytes_in": data["bytes_in"],
            "unique_dests": len(data["destinations"]),
            "destinations": sorted(data["destinations"]),
            "ports": sorted(data["ports"]),
            "protocols": sorted(data["protocols"]),
        }

        # Persist locally
        store_flow_summary(
            mac=mac,
            ip=ip,
            connections=summary["connections"],
            bytes_out=summary["bytes_out"],
            bytes_in=summary["bytes_in"],
            unique_dests=summary["unique_dests"],
            destinations=json.dumps(summary["destinations"]),
            ports=json.dumps(summary["ports"]),
            protocols=json.dumps(summary["protocols"]),
        )

        # Build and enqueue event for backend
        event = build_flow_summary(mac, summary)
        enqueue_and_dispatch(event)

        results.append(summary)

    if results:
        logger.info(
            "Flow summary: %d devices with traffic, %d total connections tracked",
            len(results), sum(s["connections"] for s in results),
        )

    return results
