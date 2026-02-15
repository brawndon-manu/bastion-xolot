"""
Bastión Xólot — Device Discovery (Phase 1)

Discovers devices on the protected LAN by parsing the system
ARP / neighbor table.  Emits `device_seen` events for every
device found, with `is_new = True` on first observation.

How it works:
  1. Runs `ip neigh show` (Linux) to read the kernel neighbor table
  2. Parses each line → extracts IP, MAC, interface, state
  3. Compares against local storage → detects new arrivals
  4. Builds device_seen events and optionally generates alerts
     for unknown devices

Prerequisites (owned by Systems Architect):
  - The Pi must be acting as an inline gateway so that devices'
    ARP entries appear in its neighbor table
  - LAN_IFACE must be configured in config.py

Data collected (metadata only — no packet payloads):
  - MAC address
  - IP address
  - Hostname (reverse DNS, best-effort)
  - First-seen / last-seen timestamps
"""

import re
import subprocess
import logging
from typing import Optional

from bastion_agent.config import LAN_IFACE
from bastion_agent.events import build_device_seen, build_alert, enqueue_and_dispatch
from bastion_agent.storage import upsert_device, get_known_device
from bastion_agent.utils import normalize_mac, is_valid_mac, resolve_hostname

logger = logging.getLogger(__name__)

# ── Regex for parsing `ip neigh` output ──
# Example lines:
#   192.168.1.1 dev eth1 lladdr aa:bb:cc:dd:ee:ff REACHABLE
#   192.168.1.50 dev eth1 lladdr 11:22:33:44:55:66 STALE
#   fe80::1 dev eth1 lladdr aa:bb:cc:dd:ee:ff router REACHABLE
_NEIGH_LINE_RE = re.compile(
    r"^(?P<ip>\S+)\s+"           # IP address (v4 or v6)
    r"dev\s+(?P<iface>\S+)\s+"   # network interface
    r"lladdr\s+(?P<mac>\S+)\s+"  # link-layer (MAC) address
    r"(?:router\s+)?"            # optional "router" flag
    r"(?P<state>\S+)"            # state: REACHABLE, STALE, DELAY, etc.
)

# States that indicate the device is (or was recently) active
_ACTIVE_STATES = {"REACHABLE", "STALE", "DELAY", "PROBE"}


def parse_neighbor_table(interface_filter: str | None = None) -> list[dict]:
    """
    Parse the Linux neighbor (ARP) table via `ip neigh show`.

    Returns a list of dicts with keys: ip, mac, interface, state.
    Filters to the specified interface if given; otherwise returns all.
    """
    try:
        result = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except FileNotFoundError:
        logger.error(
            "`ip` command not found — device discovery requires Linux "
            "iproute2 tools (available on Raspberry Pi OS)"
        )
        return []
    except subprocess.TimeoutExpired:
        logger.error("ip neigh timed out — possible system issue")
        return []

    if result.returncode != 0:
        logger.warning("ip neigh returned code %d: %s", result.returncode, result.stderr.strip())

    neighbors: list[dict] = []

    for line in result.stdout.strip().splitlines():
        match = _NEIGH_LINE_RE.match(line.strip())
        if not match:
            continue

        entry = match.groupdict()

        # Skip entries not on our LAN interface
        if interface_filter and entry["iface"] != interface_filter:
            continue

        # Skip inactive entries (FAILED, INCOMPLETE, NONE)
        if entry["state"] not in _ACTIVE_STATES:
            continue

        # Validate MAC
        mac = normalize_mac(entry["mac"])
        if not is_valid_mac(mac):
            continue

        # Skip IPv6 link-local for now (focus on IPv4 devices)
        if entry["ip"].startswith("fe80::"):
            continue

        neighbors.append({
            "ip": entry["ip"],
            "mac": mac,
            "interface": entry["iface"],
            "state": entry["state"],
        })

    return neighbors


def scan_network() -> list[dict]:
    """
    Run a full device discovery scan.

    1. Reads the neighbor table (filtered to LAN interface)
    2. For each device, checks if it's new or already known
    3. Builds device_seen events
    4. Generates an alert for brand-new devices
    5. Returns list of all generated events

    This function is called periodically by the agent main loop
    (interval configured via DISCOVERY_INTERVAL in config.py).
    """
    iface = LAN_IFACE if LAN_IFACE != "CHANGE ME" else None
    neighbors = parse_neighbor_table(interface_filter=iface)

    if not neighbors:
        logger.debug("No active neighbors found on %s", iface or "all interfaces")
        return []

    events: list[dict] = []

    for entry in neighbors:
        mac = entry["mac"]
        ip = entry["ip"]

        # Try reverse DNS for hostname
        hostname = resolve_hostname(ip)

        # Update local device store — returns True if brand new
        is_new = upsert_device(mac, ip, hostname)

        # Build device_seen event
        event = build_device_seen(
            mac_address=mac,
            ip_address=ip,
            hostname=hostname,
            is_new=is_new,
        )
        enqueue_and_dispatch(event)
        events.append(event)

        if is_new:
            logger.info("New device discovered: %s (%s) — %s", mac, ip, hostname or "no hostname")

            # Generate alert for new device arrival
            alert = build_alert(
                device_id=mac,
                severity="low",
                title="New device joined the network",
                explanation=(
                    f"A new device with address {mac} ({ip}) "
                    f"{'named ' + hostname + ' ' if hostname else ''}"
                    f"has appeared on your network. If you recognize this "
                    f"device, you can mark it as trusted. If not, consider "
                    f"investigating further."
                ),
                evidence={
                    "source_module": "discovery",
                    "details": {
                        "mac_address": mac,
                        "ip_address": ip,
                        "hostname": hostname,
                    },
                },
                recommended_action=(
                    "Check if this device belongs to your staff or business. "
                    "If you don't recognize it, you can quarantine it from the app."
                ),
                confidence=1.0,
                related_event_ids=[event["id"]],
            )
            enqueue_and_dispatch(alert)
            events.append(alert)
        else:
            logger.debug("Known device seen: %s (%s)", mac, ip)

    logger.info("Discovery scan complete: %d devices found, %d events generated",
                len(neighbors), len(events))
    return events
