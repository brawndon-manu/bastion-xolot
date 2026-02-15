"""
Bastión Xólot — Edge Agent Configuration

Central configuration for all agent modules.
Values here are defaults; override via environment variables or .env file.

NOTE: Interface names (LAN_IFACE, WAN_IFACE) must be set by the
      Systems Architect before the agent can run on real hardware.
"""

import os


# ═══════════════════════════════════════════
# Safety modes (owned by Systems Architect)
# ═══════════════════════════════════════════

# When true:
# - detection still runs
# - enforcement becomes no-op
MONITOR_ONLY = True

# When true:
# - enforcement prints commands instead of executing (for testing)
# - simulate only, never enforce
DRY_RUN = True

# When false (default):
# - enforcement is completely disabled
# - prevents accidental blocking on first boot or misconfiguration
# - must be explicitly set to True by a human operator
# NOTE: This does NOT override MONITOR_ONLY or DRY_RUN
ALLOW_ENFORCEMENT = False


# ═══════════════════════════════════════════
# Network interfaces (set by Systems Architect)
# ═══════════════════════════════════════════

# Interface facing the internal network / router
LAN_IFACE = os.getenv("BASTION_LAN_IFACE", "CHANGE ME")

# Interface facing the modem / internet
WAN_IFACE = os.getenv("BASTION_WAN_IFACE", "CHANGE ME")


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
LOCAL_DB_PATH = os.getenv(
    "BASTION_LOCAL_DB", "/var/lib/bastion-agent/agent.db"
)

# Path for agent logs
LOG_PATH = os.getenv("BASTION_LOG_PATH", "/var/log/bastion-agent.log")
LOG_LEVEL = os.getenv("BASTION_LOG_LEVEL", "INFO")


# ═══════════════════════════════════════════
# Safety gate
# ═══════════════════════════════════════════

def enforcement_allowed() -> bool:
    """
    Fail-closed safety gate: enforcement is denied unless ALL conditions
    are satisfied.  Prevents accidental blocking during setup, demos,
    or misconfiguration.
    """
    if MONITOR_ONLY:
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

