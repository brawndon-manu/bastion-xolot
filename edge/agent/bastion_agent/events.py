"""
Bastión Xólot — Unified Event Builder & Dispatcher

Provides factory functions for every event type emitted by the
detection pipeline.  Events follow the schema defined in
shared/schemas/event.schema.json.

Dispatch flow:
  1. Detection module calls build_*() → returns event dict
  2. Agent loop calls enqueue_and_dispatch() → stores locally + POSTs to backend

NOTE: The backend POST /events endpoint is owned by the Backend Engineer.
      This module posts events to that endpoint but does not implement it.
"""

import logging
from typing import Any

import httpx

from bastion_agent import __version__
from bastion_agent.config import BACKEND_URL, API_TOKEN
from bastion_agent.storage import enqueue_event
from bastion_agent.utils import utcnow_iso, new_uuid

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# Event builders (one per event type)
# ─────────────────────────────────────────────

def _base_event(event_type: str, source: str, device_id: str | None = None) -> dict:
    """Shared skeleton for all events."""
    return {
        "id": new_uuid(),
        "type": event_type,
        "timestamp": utcnow_iso(),
        "source": source,
        "device_id": device_id,
        "data": {},
        "metadata": {
            "agent_version": __version__,
        },
    }


def build_device_seen(
    mac_address: str,
    ip_address: str,
    hostname: str | None = None,
    is_new: bool = False,
) -> dict:
    """Build a device_seen event (emitted by discovery module)."""
    event = _base_event("device_seen", source="discovery", device_id=mac_address)
    event["data"] = {
        "mac_address": mac_address,
        "ip_address": ip_address,
        "hostname": hostname,
        "is_new": is_new,
    }
    return event


def build_dns_blocked(
    domain: str,
    client_ip: str,
    client_mac: str | None = None,
    block_reason: str = "blocklist",
    list_source: str | None = None,
) -> dict:
    """Build a dns_blocked event (emitted by dns_monitor module)."""
    event = _base_event("dns_blocked", source="dns_monitor", device_id=client_mac)
    event["data"] = {
        "domain": domain,
        "client_ip": client_ip,
        "block_reason": block_reason,
        "list_source": list_source,
    }
    return event


def build_dns_query(
    domain: str,
    client_ip: str,
    query_type: str = "A",
    client_mac: str | None = None,
) -> dict:
    """Build a dns_query event (informational, not blocked)."""
    event = _base_event("dns_query", source="dns_monitor", device_id=client_mac)
    event["data"] = {
        "domain": domain,
        "client_ip": client_ip,
        "query_type": query_type,
    }
    return event


# ── Phase 3 stubs ──

def build_flow_summary(device_id: str, summary_data: dict) -> dict:
    """Build a flow_summary event (Phase 3 — not yet implemented)."""
    event = _base_event("flow_summary", source="flow_summary", device_id=device_id)
    event["data"] = summary_data
    return event


def build_anomaly_detected(device_id: str, anomaly_data: dict) -> dict:
    """Build an anomaly_detected event (Phase 3 — not yet implemented)."""
    event = _base_event("anomaly_detected", source="anomaly", device_id=device_id)
    event["data"] = anomaly_data
    return event


# ─────────────────────────────────────────────
# Alert builder
# ─────────────────────────────────────────────

def build_alert(
    device_id: str,
    severity: str,
    title: str,
    explanation: str,
    evidence: dict | None = None,
    recommended_action: str | None = None,
    confidence: float = 0.8,
    related_event_ids: list[str] | None = None,
) -> dict:
    """
    Build a structured alert dict matching shared/schemas/alert.schema.json.

    Alerts are the user-facing output — every alert MUST include a
    plain-English explanation (required by the project proposal).
    """
    return {
        "id": new_uuid(),
        "device_id": device_id,
        "severity": severity,
        "title": title,
        "explanation": explanation,
        "evidence": evidence or {},
        "recommended_action": recommended_action,
        "confidence": confidence,
        "status": "active",
        "created_at": utcnow_iso(),
        "related_event_ids": related_event_ids or [],
    }


# ─────────────────────────────────────────────
# Dispatch (local queue + backend POST)
# ─────────────────────────────────────────────

def enqueue_and_dispatch(event: dict) -> None:
    """
    Store event locally and attempt to POST it to the backend.

    If the backend is unreachable, the event remains queued and
    will be retried on the next dispatch cycle.
    """
    enqueue_event(event["id"], event)
    logger.debug("Event %s (%s) queued locally", event["id"], event["type"])


async def dispatch_to_backend(events: list[dict]) -> list[str]:
    """
    POST a batch of events to the backend API.

    Returns list of event IDs that were successfully accepted.

    NOTE: The POST /events endpoint is implemented by the Backend Engineer.
    """
    if not events:
        return []

    url = f"{BACKEND_URL}/events"
    headers = {"Content-Type": "application/json"}
    if API_TOKEN:
        headers["Authorization"] = f"Bearer {API_TOKEN}"

    dispatched_ids: list[str] = []

    async with httpx.AsyncClient(timeout=10.0) as client:
        for event in events:
            try:
                resp = await client.post(url, json=event, headers=headers)
                if resp.status_code in (200, 201):
                    dispatched_ids.append(event["id"])
                    logger.debug("Dispatched event %s to backend", event["id"])
                else:
                    logger.warning(
                        "Backend rejected event %s: %s %s",
                        event["id"], resp.status_code, resp.text[:200],
                    )
            except httpx.HTTPError as exc:
                logger.warning("Failed to dispatch event %s: %s", event["id"], exc)
                break  # stop trying if backend is down

    return dispatched_ids


async def dispatch_alert_to_backend(alert: dict) -> bool:
    """
    POST an alert directly to the backend alerts endpoint.

    NOTE: The POST /alerts endpoint is implemented by the Backend Engineer.
    """
    url = f"{BACKEND_URL}/alerts"
    headers = {"Content-Type": "application/json"}
    if API_TOKEN:
        headers["Authorization"] = f"Bearer {API_TOKEN}"

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.post(url, json=alert, headers=headers)
            if resp.status_code in (200, 201):
                logger.info("Alert %s sent to backend", alert["id"])
                return True
            else:
                logger.warning(
                    "Backend rejected alert %s: %s %s",
                    alert["id"], resp.status_code, resp.text[:200],
                )
                return False
        except httpx.HTTPError as exc:
            logger.warning("Failed to send alert %s: %s", alert["id"], exc)
            return False
