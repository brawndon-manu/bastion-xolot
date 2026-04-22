import { Router } from "express";
import { 
    quarantineDevice, 
    unquarantineDevice,
    listEnforcementActions
 } from "../services/enforcement_service";

 // Create a new Express router for enforcement-related endpoints
export const enforcementRouter = Router();

// Represenets the normalized structure of an enforcement request.
type EnforcementRequest = {
    reason: string;             // Reason for enforcement (e.g., policy_violation)
    initiated_by: string;       // Who initiated the action (default: operator)
    evidence: string | null;    // Optional supporting evidence (stored as JSON string)
};

// Type gaurd to ensure a value is a plain object (not null or an array).
function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Safely reads a string value.
 *  - Returns trimmed string if valid
 *  - Returns undefined if not a valid non-empty string
 */
function readOptionalString(value: unknown): string | undefined {
    return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

/**
 * Normalizes incoming request body into a consistent EnforcementRequest format.
 *  - Applies defaults if fields are missing
 *  - Validate that body is an object
 *  - Converts evidence into a JSON string if provided
 */
function normalizeEnforcementRequest(body: unknown, defaultReason: string): EnforcementRequest {
    // If no body provided, return default enforcement request
    if (body === undefined || body === null) {
        return {
            reason: defaultReason,
            initiated_by: "operator",
            evidence: null,
        };
    }

    // Ensure request body is a valid object
    if (!isRecord(body)) {
        throw new Error("Request body must be a JSON object");
    }

    // Convert evidence to JSON string if present, otherwise null
    const evidence = body.evidence === undefined ? null : JSON.stringify(body.evidence);

    return {
        // Use provided reason or fallback default
        reason: readOptionalString(body.reason) || defaultReason,

        // Use provided initiator or default to "operator"
        initiated_by: readOptionalString(body.initiated_by) || "operator",
        evidence,
    };
}

/**
 * Centralized error handler for enforcement routes.
 *  - Logs the error
 *  - Returns appropriate HTTP status codes based on error type
 */
function sendEnforcementError(res: any, err: unknown, fallbackMessage: string) {
    console.error(fallbackMessage, err);

    if (err instanceof Error) {
        // Resource not found -> 404
        if (err.message.includes("not found")) {
            return res.status(404).json({ error: err.message });
        }

        // Invalid request format -> 400
        if (err.message.includes("Request body must")) {
            return res.status(400).json({ error: err.message });
        }
    }

    // Default -> Internal Server Error
    return res.status(500).json({ error: "Internal server error" });
}

// UUID v4 pattern — rejects obviously malformed IDs before hitting the DB
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isValidId(id: unknown): id is string {
    return typeof id === "string" && UUID_RE.test(id);
}

/**
 * Handles device quarantine requests.
 *  - Normalizes input
 *  - Calls service layer to perform action
 *  - Returns created enforcement action
 */
async function handleQuarantine(req: any, res: any) {
    if (!isValidId(req.params.id)) {
        return res.status(400).json({ error: "Invalid device ID" });
    }
    try {
        const request = normalizeEnforcementRequest(req.body, "policy_violation");
        const action = quarantineDevice(req.params.id, request.reason, {
            initiated_by: request.initiated_by,
            evidence: request.evidence,
        });

        res.status(201).json(action);
    } catch (err) {
        sendEnforcementError(res, err, "Quarantine failed:");
    }
}

// Route a quarantine a device by ID
enforcementRouter.post("/quarantine/:id", handleQuarantine);

// Handles releasing (unquarantining) a device
enforcementRouter.post("/release/:id", async (req, res) => {
    if (!isValidId(req.params.id)) {
        return res.status(400).json({ error: "Invalid device ID" });
    }
    try {
        const request = normalizeEnforcementRequest(req.body, "manual_release");
        const action = unquarantineDevice(req.params.id, {
            initiated_by: request.initiated_by,
            evidence: request.evidence,
        });
        res.status(200).json(action);
    } catch (err) {
        sendEnforcementError(res, err, "Release failed:");
    }
});

// Retrieves enforcement history.
enforcementRouter.get("/history", (req, res) => {
    try {
        const history = listEnforcementActions();
        res.json(history);
    } catch (err) {
        console.error("Failed to fetch enforcement history:", err);
        res.status(500).json({error: "Internal server error" });
    }
});