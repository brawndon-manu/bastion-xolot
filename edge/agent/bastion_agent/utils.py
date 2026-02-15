"""
Bastión Xólot — Agent Utilities

Shared helpers used across all detection modules.
"""

import re
import uuid
import socket
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ── Regex for MAC address validation ──
_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$")


def utcnow_iso() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def new_uuid() -> str:
    """Generate a new UUID-4 string."""
    return str(uuid.uuid4())


def normalize_mac(mac: str) -> str:
    """
    Normalize a MAC address to lowercase colon-separated format.

    Examples:
        "AA:BB:CC:DD:EE:FF"  →  "aa:bb:cc:dd:ee:ff"
        "AA-BB-CC-DD-EE-FF"  →  "aa:bb:cc:dd:ee:ff"
    """
    return mac.strip().lower().replace("-", ":")


def is_valid_mac(mac: str) -> bool:
    """Check whether a string is a valid MAC address."""
    return bool(_MAC_RE.match(mac))


def resolve_hostname(ip: str) -> str | None:
    """
    Attempt reverse DNS lookup for an IP address.
    Returns hostname string or None if lookup fails.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def safe_int(value: str, default: int = 0) -> int:
    """Parse an integer from a string, returning default on failure."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default
