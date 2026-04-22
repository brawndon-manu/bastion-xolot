"""
Bastión Xólot — Suricata IDS Adapter

Reads Suricata's EVE JSON log and converts IDS alerts into Bastión
events for the correlation pipeline.

Suricata EVE log format:
  - JSON-lines at /var/log/suricata/eve.json
  - event_type == "alert" lines only

File offset is tracked between calls so each cycle only ingests new lines.
"""

import ipaddress
import json
import logging
import time

from bastion_agent.utils import new_uuid, utcnow_iso

logger = logging.getLogger(__name__)


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


_RECENT_ALERT_KEYS: dict[tuple, float] = {}
_DEDUP_WINDOW_SECONDS = 120
_NOISY_SIGNATURE_PREFIXES = (
    "suricata stream ",
    "et info observed ",
    "et info session traversal utilities for nat ",
)


def _is_low_value_signature(signature: str, category: str) -> bool:
    normalized_signature = signature.lower().strip()
    normalized_category = category.lower().strip()

    if normalized_signature.startswith(_NOISY_SIGNATURE_PREFIXES):
        return True

    return "generic protocol command decode" in normalized_category


def _is_recent_duplicate(event: dict) -> bool:
    now = time.monotonic()
    cutoff = now - _DEDUP_WINDOW_SECONDS

    for key, seen_at in list(_RECENT_ALERT_KEYS.items()):
        if seen_at < cutoff:
            del _RECENT_ALERT_KEYS[key]

    key = (
        event.get("device_id"),
        event.get("signature_id") or event.get("signature"),
        event.get("src_ip"),
        event.get("dest_ip"),
        event.get("dest_port"),
        event.get("proto"),
    )

    if key in _RECENT_ALERT_KEYS:
        return True

    _RECENT_ALERT_KEYS[key] = now
    return False


# Tracks how far into eve.json we've already read.
# This is process-local; on a fresh agent start we intentionally begin at EOF
# so historical Suricata noise does not flood the backend queue.
_eve_log_offset: int = 0
_eve_log_initialized: bool = False


def parse_eve_log(log_path: str = "/var/log/suricata/eve.json") -> list[dict]:
    """
    Read new Suricata alert events since the last call.

    Returns a list of normalized Bastion event dicts ready for enqueue_event().
    """
    global _eve_log_offset, _eve_log_initialized

    events: list[dict] = []

    try:
        with open(log_path, "r") as f:
            f.seek(0, 2)
            log_size = f.tell()

            if not _eve_log_initialized:
                _eve_log_offset = log_size
                _eve_log_initialized = True
                logger.info("Initialized EVE log offset at end of file: %s", log_path)
                return events

            if _eve_log_offset > log_size:
                logger.info("EVE log appears rotated or truncated; restarting at current end")
                _eve_log_offset = log_size
                return events

            f.seek(_eve_log_offset)

            for line in f:
                if not line.strip():
                    continue

                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    logger.warning("Skipping malformed JSON line in EVE log")
                    continue

                if data.get("event_type") != "alert":
                    continue

                alert = data.get("alert", {})

                src_ip = data.get("src_ip")
                dest_ip = data.get("dest_ip")

                if data.get("src_mac"):
                    device_id = data["src_mac"]
                    device_id_type = "mac"
                elif src_ip and _is_private(src_ip):
                    # Outbound alert — local device is the source
                    device_id = src_ip
                    device_id_type = "ip"
                elif dest_ip and _is_private(dest_ip):
                    # Inbound alert — local device is the destination
                    device_id = dest_ip
                    device_id_type = "ip"
                else:
                    continue

                sev_map = {1: "high", 2: "medium", 3: "low"}
                severity = sev_map.get(alert.get("severity"), "low")
                signature = alert.get("signature", "")
                category = alert.get("category", "")

                if _is_low_value_signature(signature, category):
                    continue

                event = {
                    "id": new_uuid(),
                    "type": "ids_alert",
                    "timestamp": data.get("timestamp", utcnow_iso()),
                    "source": "suricata",
                    "device_id": device_id,
                    "device_id_type": device_id_type,
                    "severity": severity,
                    "signature": signature,
                    "reason": signature or "suricata alert",
                    "category": category,
                    "signature_id": alert.get("signature_id"),
                    "src_ip": data.get("src_ip"),
                    "dest_ip": data.get("dest_ip"),
                    "dest_port": data.get("dest_port"),
                    "proto": data.get("proto"),
                }

                if _is_recent_duplicate(event):
                    continue

                events.append(event)

            _eve_log_offset = f.tell()

    except FileNotFoundError:
        logger.warning("EVE log not found: %s", log_path)
    except Exception:
        logger.exception("Failed to parse EVE log")

    return events
