import { Router } from "express";
import { ensureDeviceExists } from "../services/device_service";
import { broadcast } from "../realtime/websocket";
import { processEvent } from "../services/correlation_service";

// Create a router for handling incoming event data
export const eventsRouter = Router();

/**
 * Represents a normalized event structure after validation and cleanup.
 * Extends a generic object but enforces required fields.
 */
type NormalizedEvent = Record<string, unknown> & {
    id?: string;                    // Optional event ID
    type: string;                   // Required event type (e.g., login, ids_alert)
    device_id: string;              // Unique identifier for the device
    device_id_type?: string;        // Optional hint from edge adapters (e.g., mac, ip)
    mac_address?: string;           // Optional MAC address
    ip?: string;                    // Optional IP (alias)
    ip_address?: string;            // Optional IP address (canonical)
    hostname?: string;              // Optional hostname
    signature?: string;             // Required for IDS alerts
    timestamp?: string | number;    // Optional timestamp (ISO string or epoch)
};

/**
 * Type guard to ensure a value is a plain object.
 */
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

/**
 * Detects the legacy Suricata adapter payload shape from main.
 * That adapter currently emits reason + severity + device_id_type, but no explicit type.
 */
function inferEventType(payload: Record<string, unknown>): string | undefined {
    const explicitType = readOptionalString(payload.type);
    if (explicitType) {
        return explicitType;
    }

    const deviceIdType = readOptionalString(payload.device_id_type);
    const reason = readOptionalString(payload.reason);
    const severity = readOptionalString(payload.severity);

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
 *  - Enforces additional rules for specific event types
 */
function normalizeEventPayload(payload: unknown): { event?: NormalizedEvent; error?: string } {
    // Ensure payload is a valid object
    if (!isRecord(payload)) {
        return { error: "Event payload must be a JSON object" };
    }

    // Validate required event type, or infer it for legacy adapter payloads.
    const type = inferEventType(payload);
    if (!type) {
        return { error: "Event type is required" };
    }

    // Extract possible device identifiers.
    const deviceIdType = readOptionalString(payload.device_id_type);
    const explicitDeviceId = readOptionalString(payload.device_id);
    let macAddress = readOptionalString(payload.mac_address);
    let ipAddress = readOptionalString(payload.ip_address) || readOptionalString(payload.ip);
    const hostname = readOptionalString(payload.hostname);

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
        return { error: "Event must include device_id, mac_address, ip, ip_address, or hostname" };
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
        normalized.mac_address = macAddress.toLowerCase();  // Normalize MAC to lowercase
    }

    if (ipAddress) {
        normalized.ip = ipAddress;
        normalized.ip_address = ipAddress;                  // Ensure both fields are consistent
    }

    if (hostname) {
        normalized.hostname = hostname;
    }

    // Special validation for IDS alerts.
    if (type === "ids_alert") {
        const signature = readOptionalString(payload.signature) || readOptionalString(payload.reason);
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
 *  - Validates and normalizes payload
 *  - Ensures device exists (or creates it)
 *  - Processes event via correlation engine
 *  - Broadcasts the event in real-time if not duplicate
 */
eventsRouter.post("/", async (req, res) => {
    try {
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
            hostname: event.hostname
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
        console.error("Event ingestion failed:", err);
        res.status(500).json({ error: "Internal server error"});
    }
});