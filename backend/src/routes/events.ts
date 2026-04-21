import { Router } from "express";
import { buildAlertFingerprint, createAlert, findRecentActiveAlert, refreshAlert } from "../services/alert_service";
import { ensureDeviceExists } from "../services/device_service";
import { broadcast } from "../realtime/websocket";
import { processEvent } from "../services/correlation_service";
import { logger } from "../utils/logger";

// Create a router for handling incoming event data
export const eventsRouter = Router();

/**
 * Represents a normalized event structure after validation and cleanup.
 * Extends a generic object but enforces required fields.
 */
type NormalizedEvent = Record<string, unknown> & {
    id?: string;                    // Optional event ID
    type: string;                   // Required event type (e.g., dns_block, ids_alert)
    device_id: string;              // Unique identifier for the device
    device_id_type?: string;        // Optional hint from edge adapters (e.g., mac, ip)
    mac_address?: string;           // Optional MAC address
    ip?: string;                    // Optional IP (alias)
    ip_address?: string;            // Optional IP address (canonical)
    hostname?: string;              // Optional hostname
    signature?: string;             // Required for IDS alerts
    timestamp?: string | number;    // Optional timestamp (ISO string or epoch)
};

type EdgeAlertPayload = Record<string, unknown> & {
    id?: string;
    device_id: string;
    severity: string;
    title: string;
    explanation: string;
    created_at?: string;
};

// Type guard to ensure a value is a plain object.
function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Safely extracts a trimmed string.
 * Returns undefined if the value is not a valid non-empty string.
 */
function readOptionalString(value: unknown): string | undefined {
    return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function readOptionalNumber(value: unknown): number | undefined {
    if (typeof value === "number" && Number.isFinite(value)) {
        return value;
    }

    if (typeof value === "string" && value.trim()) {
        const parsed = Number(value);
        if (Number.isFinite(parsed)) {
            return parsed;
        }
    }

    return undefined;
}

/**
 * The edge agent sends a nested event envelope with most event-specific fields
 * inside payload.data. This helper extracts that object when present.
 */
function getEventData(payload: Record<string, unknown>): Record<string, unknown> {
    return isRecord(payload.data) ? payload.data : {};
}

/**
 * Detects alert-shaped payloads currently emitted by the edge agent modules.
 * 
 * The edge runtime still queues some locally-built alerts into the event queue.
 * The backend keeps the integration stable by accepting and storing them here
 * instead of rejecting them as malformed events.
 */
function normalizeEdgeAlertPayload(payload: unknown): { alert?: EdgeAlertPayload; error?: string } {
    if (!isRecord(payload)) {
        return {};
    }

    if (readOptionalString(payload.type) || readOptionalString(payload.source)) {
        return {};
    }

    const deviceId = readOptionalString(payload.device_id);
    const severity = readOptionalString(payload.severity);
    const title = readOptionalString(payload.title);
    const explanation = readOptionalString(payload.explanation);

    if (!deviceId || !severity || !title || !explanation) {
        return {};
    }

    return {
        alert: {
            ...payload,
            id: readOptionalString(payload.id),
            device_id: deviceId,
            severity,
            title,
            explanation,
            created_at: readOptionalString(payload.created_at),
        },
    };
}

// Normalizes edge event names into the backend event types used by correlation.
function mapEventType(type: string): string {
    switch (type) {
        case "dns_blocked":
            return "dns_block";
        default:
            return type;
    }
}

// Detects the legacy Suricata adapter payload shape from main.
function inferEventType(payload: Record<string, unknown>, data: Record<string, unknown>): string | undefined {
    const explicitType = readOptionalString(payload.type);
    if (explicitType) {
        return mapEventType(explicitType);
    }

    const deviceIdType = readOptionalString(payload.device_id_type);
    const reason = readOptionalString(payload.reason) || readOptionalString(data.reason);
    const severity = readOptionalString(payload.severity) || readOptionalString(data.severity);

    if (reason && (deviceIdType === "mac" || deviceIdType === "ip" || severity)) {
        return "ids_alert";
    }

    return undefined;
}

/**
 * Validates and normalizes incoming event payload.
 *  - Ensures required fields exist
 *  - Standardizes field names (e.g., ip vs ip_address)
 *  - Applies fallback logic for device identification
 *  - Accepts the current Suricata adapter stub output from main
 *  - Accepts the edge agent envelope from edge/agent/bastion_agent/events.py
 *  - Enforces additional rules for specific event types
 */
function normalizeEventPayload(payload: unknown): { event?: NormalizedEvent; error?: string } {
    
    // Ensure payload is a valid object
    if (!isRecord(payload)) {
        return { error: "Event payload must be a JSON object" };
    }

    const data = getEventData(payload);

    // Validate required event type, or infer it for legacy adapter payloads.
    const type = inferEventType(payload, data);
    if (!type) {
        return { error: "Event type is required" };
    }

    // Extract possible device identifiers.
    const deviceIdType = readOptionalString(payload.device_id_type);
    const explicitDeviceId =
        readOptionalString(payload.device_id) ||
        readOptionalString(data.mac_address) ||
        readOptionalString(data.client_mac) ||
        readOptionalString(data.client_ip) ||
        readOptionalString(data.ip_address);

    let macAddress =
        readOptionalString(payload.mac_address) ||
        readOptionalString(data.mac_address) ||
        readOptionalString(data.client_mac);

    let ipAddress =
        readOptionalString(payload.ip_address) ||
        readOptionalString(payload.ip) ||
        readOptionalString(data.ip_address) ||
        readOptionalString(data.client_ip);

    const hostname =
        readOptionalString(payload.hostname) ||
        readOptionalString(data.hostname);

    // The current Suricata adapter provides device_id plus a device_id_type hint.
    if (!macAddress && deviceIdType === "mac" && explicitDeviceId) {
        macAddress = explicitDeviceId;
    }
    if (!ipAddress && deviceIdType === "ip" && explicitDeviceId) {
        ipAddress = explicitDeviceId;
    }

    // Determine device ID using priority fallback.
    const deviceId = explicitDeviceId || macAddress || ipAddress || hostname;

    if (!deviceId) {
        return { error: "Event must include device_id, mac_address, ip, ip_address, client_ip, or hostname" };
    }

    // Build normalized event object.
    const normalized: NormalizedEvent = {
        ...payload,
        type,
        device_id: deviceId,
    };

    // Normalize optional fields.
    const eventId = readOptionalString(payload.id);
    if (eventId) {
        normalized.id = eventId;
    }

    if (deviceIdType) {
        normalized.device_id_type = deviceIdType;
    }

    if (macAddress) {
        normalized.mac_address = macAddress.toLowerCase();
    }

    if (ipAddress) {
        normalized.ip = ipAddress;
        normalized.ip_address = ipAddress;
    }

    if (hostname) {
        normalized.hostname = hostname;
    }

    // Flatten common edge-agent fields so backend services do not need to know about payload.data.
    const domain = readOptionalString(payload.domain) || readOptionalString(data.domain);
    if (domain) {
        normalized.domain = domain;
    }

    const source = readOptionalString(payload.source);
    if (source) {
        normalized.source = source;
    }

    const severity = readOptionalString(payload.severity) || readOptionalString(data.severity);
    if (severity) {
        normalized.severity = severity;
    }

    // Flow summaries from the edge agent use Phase 3 field names that differ from backend storage names.
    const flowCount = readOptionalNumber(payload.flow_count) ?? readOptionalNumber(data.connections);
    if (flowCount !== undefined) {
        normalized.flow_count = flowCount;
    }

    const bytesOut = readOptionalNumber(data.bytes_out) ?? 0;
    const bytesIn = readOptionalNumber(data.bytes_in) ?? 0;
    const totalBytes = readOptionalNumber(payload.total_bytes) ?? (bytesOut + bytesIn);
    if (totalBytes > 0) {
        normalized.total_bytes = totalBytes;
        normalized.bytes = totalBytes;
    }

    const uniqueDestinations =
        readOptionalNumber(payload.unique_destinations) ??
        readOptionalNumber(data.unique_dests);
    if (uniqueDestinations !== undefined) {
        normalized.unique_destinations = uniqueDestinations;
    }

    const destinationList = Array.isArray(data.destinations) ? data.destinations : undefined;
    if (!normalized.destination && destinationList && destinationList.length > 0) {
        normalized.destination = destinationList[0];
    }

    if (type === "device_seen") {
        const isNew = payload.is_new ?? data.is_new;
        if (typeof isNew === "boolean") {
            normalized.is_new = isNew;
        }
    }

    if (type === "anomaly_detected") {
        const anomalyType = readOptionalString(data.anomaly_type);
        const reason = readOptionalString(payload.reason) || anomalyType;
        if (reason) {
            normalized.reason = reason;
        }
    }

    // Special validation for IDS alerts.
    if (type === "ids_alert") {
        const signature =
            readOptionalString(payload.signature) ||
            readOptionalString(payload.reason) ||
            readOptionalString(data.signature) ||
            readOptionalString(data.reason);
        if (!signature) {
            return { error: "ids_alert events must include signature or reason" };
        }
        normalized.signature = signature;
    }

    // Validate timestamp format if provided.
    if (payload.timestamp !== undefined) {
        const timestamp = payload.timestamp;
        if (typeof timestamp !== "number" && typeof timestamp !== "string") {
            return { error: "timestamp must be a number or ISO date string" };
        }
        normalized.timestamp = timestamp;
    }

    return { event: normalized };
}

/**
 * POST /events
 * Handles incoming event ingestion.
 *  - Accepts edge-built alert payloads for compatibility
 *  - Validates and normalizes event payloads
 *  - Ensures device exists (or creates it)
 *  - Processes event via correlation engine
 *  - Broadcasts the event in real-time if not duplicate
 */
eventsRouter.post("/", async (req, res) => {
    try {
        const directAlert = normalizeEdgeAlertPayload(req.body);
        if (directAlert.alert) {
            const { device_id, severity, title, explanation } = directAlert.alert;
            const fingerprint = buildAlertFingerprint([device_id, "edge_alert", title]);
            const dedupWindowMs = 24 * 60 * 60 * 1000; // 24 hours — same condition shouldn't stack up all day
            const existing = findRecentActiveAlert(device_id, fingerprint, Date.now() - dedupWindowMs);

            if (existing) {
                const refreshed = refreshAlert(existing.id, {
                    explanation,
                    evidence: JSON.stringify(req.body),
                    confidence: Math.max(existing.confidence ?? 0, readOptionalNumber(req.body.confidence) ?? 0),
                });
                broadcast("alert.updated", refreshed);
                return res.status(200).json({ alert: refreshed, accepted_as: "edge_alert" });
            }

            const alert = createAlert({
                device_id,
                type: "edge_alert",
                severity,
                title,
                explanation,
                evidence: JSON.stringify(req.body),
                fingerprint,
                confidence: readOptionalNumber(req.body.confidence),
            });

            broadcast("alert.created", alert);
            return res.status(201).json({ alert, accepted_as: "edge_alert" });
        }

        // Normalize and validate incoming request body.
        const normalized = normalizeEventPayload(req.body);
        if (!normalized.event) {
            return res.status(400).json({ error: normalized.error });
        }

        const event = normalized.event;
        const device = ensureDeviceExists({
            id: event.device_id,
            mac_address: event.mac_address,
            ip_address: event.ip_address,
            hostname: event.hostname,
            vendor: event.vendor as string | undefined,
        });

        // Process event through correlation engine.
        const result = await processEvent(event, device.id);

        // Broadcast event to connected clients if it's not a duplicate.
        if (!result.duplicate) {
            broadcast("event.received", result.event);
        }

        // Return 201 for new events, 200 for duplicates.
        res.status(result.duplicate ? 200 : 201).json(result);

    } catch (err) {
        logger.error("Event ingestion failed", {
            error: err instanceof Error ? err.message : String(err),
        });
        res.status(500).json({ error: "Internal server error"});
    }
});
