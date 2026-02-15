/**
 * Bastión Xólot — Event Types
 *
 * Mirrors: shared/schemas/event.schema.json
 * Used by: backend (event ingestion, correlation) and mobile (display)
 *
 * Events are the universal data unit emitted by the edge agent.
 * Every detection module produces events; the backend stores and
 * correlates them into alerts.
 */

export type EventType =
  | "device_seen"
  | "dns_blocked"
  | "dns_query"
  | "flow_summary"
  | "anomaly_detected"
  | "enforcement_action";

export interface EventMetadata {
  agent_version?: string;
  gateway_hostname?: string;
  [key: string]: unknown;
}

export interface BastionEvent {
  id: string;
  type: EventType;
  timestamp: string; // ISO-8601
  source: string; // module name that generated this event
  device_id?: string; // MAC address when device-specific
  data?: Record<string, unknown>; // event-type-specific payload
  metadata?: EventMetadata;
}

/* ── Event-specific data shapes ── */

/** data payload for type = "device_seen" */
export interface DeviceSeenData {
  mac_address: string;
  ip_address: string;
  hostname?: string | null;
  is_new: boolean; // true on first observation
}

/** data payload for type = "dns_blocked" */
export interface DnsBlockedData {
  domain: string;
  client_ip: string;
  block_reason: string; // e.g. "blocklist", "sinkhole"
  list_source?: string; // which blocklist matched
}

/** data payload for type = "dns_query" (informational, not blocked) */
export interface DnsQueryData {
  domain: string;
  client_ip: string;
  query_type: string; // A, AAAA, CNAME, etc.
}
