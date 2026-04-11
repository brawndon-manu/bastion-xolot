"""
Bastión Xólot — Gateway Probe Monitor (Phase 9B)

Parses nftables kernel log lines emitted by the observation-only rule:

    BASTION_GW_TCP_NEW

Purpose:
- Detect gateway-targeted TCP service attempts from LAN devices
- Provide a second telemetry source beyond conntrack summaries
- Stay metadata-only and advisory-first

Current scope:
- Reads recent kernel log lines via journalctl
- Extracts SRC, DST, DPT, PROTO, and source MAC
- Returns structured raw records
- Summarizes raw records into compact per-source/per-target batches
- Converts strong summaries into normalized detection signals
"""

from __future__ import annotations

import logging
import re
import subprocess
from typing import Any

logger = logging.getLogger(__name__)

_PREFIX = "BASTION_GW_TCP_NEW"

_SRC_RE = re.compile(r"\bSRC=([0-9.]+)\b")
_DST_RE = re.compile(r"\bDST=([0-9.]+)\b")
_DPT_RE = re.compile(r"\bDPT=(\d+)\b")
_PROTO_RE = re.compile(r"\bPROTO=([A-Z0-9]+)\b")
_IN_RE = re.compile(r"\bIN=([A-Za-z0-9_.:-]+)\b")
_OUT_RE = re.compile(r"\bOUT=([A-Za-z0-9_.:-]*)\b")
_MAC_RE = re.compile(
    r"\bMAC=([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}):([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}):"
)


def _extract(pattern: re.Pattern[str], line: str) -> str | None:
    match = pattern.search(line)
    return match.group(1) if match else None


def _parse_line(line: str) -> dict[str, Any] | None:
    if _PREFIX not in line:
        return None

    src_ip = _extract(_SRC_RE, line)
    dst_ip = _extract(_DST_RE, line)
    dpt = _extract(_DPT_RE, line)
    proto = _extract(_PROTO_RE, line)
    iif = _extract(_IN_RE, line)
    oif = _extract(_OUT_RE, line)

    mac_match = _MAC_RE.search(line)
    dst_mac = mac_match.group(1).lower() if mac_match else None
    src_mac = mac_match.group(2).lower() if mac_match else None

    if not src_ip or not dst_ip or not dpt or not proto:
        return None

    return {
        "source": "gateway_probe_monitor",
        "log_prefix": _PREFIX,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": int(dpt),
        "protocol": proto.lower(),
        "iifname": iif,
        "oifname": oif,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "raw": line.strip(),
    }


def collect_gateway_probe_logs(since: str = "2 minutes ago") -> list[dict[str, Any]]:
    """
    Read recent kernel logs and extract BASTION_GW_TCP_NEW records.
    """
    try:
        result = subprocess.run(
            ["journalctl", "-k", "--since", since, "--no-pager"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except Exception:
        logger.exception("Failed to execute journalctl for gateway probe logs")
        return []

    if result.returncode != 0:
        logger.warning("journalctl returned non-zero exit status: %s", result.returncode)
        return []

    records: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        parsed = _parse_line(line)
        if parsed:
            records.append(parsed)

    if records:
        logger.info("Collected %d gateway probe log records", len(records))

    return records


def summarize_gateway_probe_logs(since: str = "2 minutes ago") -> list[dict[str, Any]]:
    """
    Summarize raw gateway probe log records into compact per-source/per-target batches.

    Grouping key:
      - src_mac
      - src_ip
      - dst_ip
      - protocol
    """
    rows = collect_gateway_probe_logs(since)
    if not rows:
        return []

    buckets: dict[tuple[Any, ...], dict[str, Any]] = {}

    for row in rows:
        key = (
            row.get("src_mac"),
            row.get("src_ip"),
            row.get("dst_ip"),
            row.get("protocol"),
        )

        if key not in buckets:
            buckets[key] = {
                "source": "gateway_probe_monitor_summary",
                "src_mac": row.get("src_mac"),
                "src_ip": row.get("src_ip"),
                "dst_mac": row.get("dst_mac"),
                "dst_ip": row.get("dst_ip"),
                "protocol": row.get("protocol"),
                "iifname": row.get("iifname"),
                "oifname": row.get("oifname"),
                "attempt_count": 0,
                "dst_ports_set": set(),
                "raw_samples": [],
            }

        bucket = buckets[key]
        bucket["attempt_count"] += 1
        bucket["dst_ports_set"].add(int(row["dst_port"]))

        if len(bucket["raw_samples"]) < 5:
            bucket["raw_samples"].append(row["raw"])

    summaries: list[dict[str, Any]] = []
    for bucket in buckets.values():
        ports = sorted(bucket.pop("dst_ports_set"))
        bucket["dst_ports"] = ports
        bucket["unique_ports_touched"] = len(ports)
        summaries.append(bucket)

    summaries.sort(
        key=lambda item: (
            item["unique_ports_touched"],
            item["attempt_count"],
            item["src_ip"] or "",
        ),
        reverse=True,
    )

    if summaries:
        logger.info("Summarized gateway probe logs into %d grouped records", len(summaries))

    return summaries


def gateway_probe_summary_to_signal(summary: dict[str, Any]) -> dict[str, Any] | None:
    """
    Convert a summarized gateway probe record into a normalized detection signal.

    Conservative first-pass thresholds:
      - target must be the gateway IP
      - at least 4 unique ports touched
      - at least 8 total attempts
      - must have a resolved MAC to be eligible for enforcement-aware policy flow
    """
    dst_ip = summary.get("dst_ip")
    src_mac = summary.get("src_mac")
    src_ip = summary.get("src_ip")
    unique_ports = int(summary.get("unique_ports_touched", 0) or 0)
    attempts = int(summary.get("attempt_count", 0) or 0)
    ports = list(summary.get("dst_ports", []))

    if dst_ip != "192.168.50.1":
        return None

    if not src_mac:
        return None

    if unique_ports < 4:
        return None

    if attempts < 8:
        return None

    return {
        "source": "gateway_probe_monitor",
        "device_id": src_mac,
        "device_id_type": "mac",
        "severity": "medium",
        "reason": (
            f"gateway_tcp_probe target={dst_ip} "
            f"ports={unique_ports} attempts={attempts} "
            f"dst_ports={','.join(str(p) for p in ports)}"
        ),
        "evidence": {
            "src_mac": src_mac,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": summary.get("protocol"),
            "attempt_count": attempts,
            "unique_ports_touched": unique_ports,
            "dst_ports": ports,
            "raw_samples": summary.get("raw_samples", []),
        },
    }


def build_gateway_probe_signals(since: str = "2 minutes ago") -> list[dict[str, Any]]:
    """
    Build normalized detection signals from summarized gateway probe logs.
    """
    signals: list[dict[str, Any]] = []

    for summary in summarize_gateway_probe_logs(since):
        signal = gateway_probe_summary_to_signal(summary)
        if signal:
            signals.append(signal)

    if signals:
        logger.info("Built %d normalized gateway probe signals", len(signals))

    return signals


def route_gateway_probe_signals(since: str = "2 minutes ago") -> list[dict[str, Any]]:
    """
    Route normalized gateway probe signals into the existing detection policy engine.

    Returns a list of:
      - signal
      - detection_result
    """
    from bastion_agent.detection import handle_event

    routed: list[dict[str, Any]] = []

    for signal in build_gateway_probe_signals(since):
        result = handle_event(signal)
        routed.append({
            "signal": signal,
            "detection_result": result,
        })

    return routed
