"""
Bastión Xólot — Edge Agent Configuration

Central configuration for all agent modules.
Values here are defaults; override via environment variables or .env file.

NOTE: Interface names (LAN_IFACE, WAN_IFACE) must be set by the
      Systems Architect before the agent can run on real hardware.
"""

import os
from dotenv import load_dotenv

load_dotenv()

PROTECTED_MACS = set(
    mac.strip().lower()
    for mac in os.getenv("PROTECTED_MACS", "").split(",")
    if mac.strip()
)


# ═══════════════════════════════════════════
# Safety modes (owned by Systems Architect)
# ═══════════════════════════════════════════

# When true:
# - detection still runs
# - enforcement becomes no-op
# Dynamically synced from the backend /health endpoint at runtime.
# The hardcoded default is True (safe) until the first successful poll.
MONITOR_ONLY = True

# When true: enforcement prints commands instead of executing.
# Set BASTION_DRY_RUN=false in .env to enable real enforcement.
DRY_RUN = os.getenv("BASTION_DRY_RUN", "true").lower() not in ("false", "0", "no")

# Master enforcement gate — must be explicitly enabled via env var.
# Set BASTION_ALLOW_ENFORCEMENT=true in .env to allow nft rules to fire.
ALLOW_ENFORCEMENT = os.getenv("BASTION_ALLOW_ENFORCEMENT", "false").lower() in (
    "true",
    "1",
    "yes",
)


# ═══════════════════════════════════════════
# Network interfaces (set by Systems Architect)
# ═══════════════════════════════════════════

# Interface facing the internal network / router
LAN_IFACE = os.getenv("BASTION_LAN_IFACE", "CHANGE ME")

# Interface facing the modem / internet
WAN_IFACE = os.getenv("BASTION_WAN_IFACE", "CHANGE ME")

# IP address of the local gateway (router)
# Used by anomaly detection and gateway probe monitor to identify gateway-directed traffic
GATEWAY_IP = os.getenv("BASTION_GATEWAY_IP", "192.168.50.1")


# ═══════════════════════════════════════════
# Backend connection (set by Backend Engineer)
# ═══════════════════════════════════════════

# URL of the backend API that receives events
BACKEND_URL = os.getenv("BASTION_BACKEND_URL", "http://localhost:3000")

# Pairing token for authenticating with the backend
# NOTE: Auth endpoint implementation is owned by Backend Engineer
API_TOKEN = os.getenv("BASTION_API_TOKEN", "")


# ═══════════════════════════════════════════
# Detection — Discovery (Phase 1)
# ═══════════════════════════════════════════

# How often (seconds) to scan the ARP / neighbor table for devices
DISCOVERY_INTERVAL = int(os.getenv("BASTION_DISCOVERY_INTERVAL", "30"))


# ═══════════════════════════════════════════
# Detection — DNS monitoring (Phase 2)
# ═══════════════════════════════════════════

# Path to dnsmasq log file
# NOTE: Actual DNS sinkhole setup is owned by Systems Architect
#       (see infra/scripts/setup_dns_sinkhole.sh)
#
# Common locations:
#   - dnsmasq default:    /var/log/dnsmasq.log
#   - syslog integration: /var/log/syslog  (grep for "dnsmasq")
#   - Pi-hole style:      /var/log/pihole.log
DNS_LOG_PATH = os.getenv("BASTION_DNS_LOG_PATH", "/var/log/dnsmasq.log")

# Path to the blocklist file used by dnsmasq
# Format: one domain per line, or dnsmasq address=/ entries
DNS_BLOCKLIST_PATH = os.getenv(
    "BASTION_DNS_BLOCKLIST_PATH", "/etc/dnsmasq.d/blocklist.conf"
)

# How often (seconds) to check for new DNS log entries
# (used as fallback if filesystem events are unavailable)
DNS_POLL_INTERVAL = int(os.getenv("BASTION_DNS_POLL_INTERVAL", "5"))


# ═══════════════════════════════════════════
# Detection — Flow & baseline (Phase 3 stubs)
# ═══════════════════════════════════════════

# How often (seconds) to summarize traffic metadata
FLOW_SUMMARY_INTERVAL = int(os.getenv("BASTION_FLOW_INTERVAL", "60"))

# Minimum observation period (hours) before baseline is considered stable
BASELINE_LEARNING_HOURS = int(os.getenv("BASTION_BASELINE_HOURS", "24"))


# ═══════════════════════════════════════════
# Local storage
# ═══════════════════════════════════════════

# Path for the agent's local SQLite database
LOCAL_DB_PATH = os.getenv("BASTION_LOCAL_DB", "/var/lib/bastion-agent/agent.db")

# Path for agent logs
LOG_PATH = os.getenv("BASTION_LOG_PATH", "/var/log/bastion-agent.log")
LOG_LEVEL = os.getenv("BASTION_LOG_LEVEL", "INFO")

EVENT_QUEUE_MAX_SIZE = int(os.getenv("BASTION_QUEUE_MAX_SIZE", "10000"))
EVENT_QUEUE_TTL_SECONDS = int(os.getenv("BASTION_QUEUE_TTL", "7200"))


# ═══════════════════════════════════════════
# Safety gate
# ═══════════════════════════════════════════

import threading
import time as _time
import urllib.request

_monitor_only_lock = threading.Lock()
_monitor_only_cache: bool = True  # fail-closed default
_monitor_only_last_fetch: float = 0.0
_MONITOR_ONLY_TTL = 30.0  # seconds between polls


def get_monitor_only() -> bool:
    """
    Returns the current monitor-only state, synced from the backend /health
    endpoint at most every 30 seconds. Falls back to True (safe) on error.
    """
    global _monitor_only_cache, _monitor_only_last_fetch
    with _monitor_only_lock:
        if _time.monotonic() - _monitor_only_last_fetch < _MONITOR_ONLY_TTL:
            return _monitor_only_cache
        try:
            url = f"{BACKEND_URL}/health"
            with urllib.request.urlopen(url, timeout=3) as resp:
                import json as _json

                data = _json.loads(resp.read())
            _monitor_only_cache = bool(data.get("monitor_only", True))
            _monitor_only_last_fetch = _time.monotonic()
        except Exception:
            pass  # keep cached value
    return _monitor_only_cache


def enforcement_allowed() -> bool:
    """
    Fail-closed safety gate: enforcement is denied unless ALL conditions
    are satisfied.  Prevents accidental blocking during setup, demos,
    or misconfiguration.
    """
    if get_monitor_only():
        return False
    if DRY_RUN:
        return False
    if not ALLOW_ENFORCEMENT:
        return False
    if LAN_IFACE == WAN_IFACE:
        return False
    if LAN_IFACE == "CHANGE ME" or WAN_IFACE == "CHANGE ME":
        return False
    if not LAN_IFACE.strip() or not WAN_IFACE.strip():
        return False

    return True


_device_roles_lock = threading.Lock()
_device_roles_cache: dict[str, str] = {}
_device_roles_last_fetch: float = 0.0
_DEVICE_ROLES_TTL = 60.0


def get_device_role(mac: str) -> str:
    global _device_roles_cache, _device_roles_last_fetch

    if mac.lower() in {m.lower() for m in PROTECTED_MACS}:
        return "infrastructure"

    with _device_roles_lock:
        if _time.monotonic() - _device_roles_last_fetch >= _DEVICE_ROLES_TTL:
            try:
                url = f"{BACKEND_URL}/devices"
                with urllib.request.urlopen(url, timeout=5) as resp:
                    import json as _json

                    devices = _json.loads(resp.read())
                _device_roles_cache = {
                    d["mac_address"].lower(): d.get("role", "unknown")
                    for d in devices
                    if d.get("mac_address")
                }
                _device_roles_last_fetch = _time.monotonic()
            except Exception:
                pass

    return _device_roles_cache.get(mac.lower(), "unknown")


def operator_enforcement_allowed() -> bool:
    """
    Looser gate for operator-initiated actions — bypasses monitor_only
    but still requires hardware config and explicit ALLOW_ENFORCEMENT.
    """
    if DRY_RUN:
        return False
    if not ALLOW_ENFORCEMENT:
        return False
    if LAN_IFACE == WAN_IFACE:
        return False
    if LAN_IFACE == "CHANGE ME" or WAN_IFACE == "CHANGE ME":
        return False
    if not LAN_IFACE.strip() or not WAN_IFACE.strip():
        return False
    return True
