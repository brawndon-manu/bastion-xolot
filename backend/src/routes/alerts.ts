import { Router } from "express";
import { getAlert, listAlerts } from "../services/alert_service";
import { logger } from "../utils/logger";

/**
 * Router responsible for alert retrieval endpoints.
 * 
 * These endpoints are consumed by:
 *  - Mobile application UI
 * 
 * This module does NOT contain business logic
 * Only handles:
 *  - HTTP request parsing
 *  - response formatting
 *  - error handling
 */
export const alertsRouter = Router();

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
 * GET /alerts
 * 
 * Returns alerts stored in the system, optionally filtered for the needs of
 * the mobile UI, demo views, or operator troubleshooting.
 */
alertsRouter.get("/", async (req, res) => {
    try {
        const filters = {
            status: readOptionalString(req.query.status),
            device_id: readOptionalString(req.query.device_id),
            type: readOptionalString(req.query.type),
            severity: readOptionalString(req.query.severity),
            since: readOptionalNumber(req.query.since),
            limit: readOptionalNumber(req.query.limit),
        };

        // Request alert list from service layer
        const alerts = await listAlerts(filters);

        // Send alerts as JSON response
        res.json(alerts);

    } catch (err) {
        // Log internal failure for debugging and audit visibility
        logger.error("Failed to fetch alerts", {
            error: err instanceof Error ? err.message : String(err),
            query: req.query,
        });

        // Generic error response for client safety
        res.status(500).json({ error: "Internal server error" });
    }
});

/**
 * Get /alerts/:id
 * 
 * Returns a single alert by its unique identifier.
 * 
 * Parameters:
 *  id - unique alert identifier (UUID expected in future phases)
 * 
 * Behavior:
 *  - Validates presence of identifier
 *  - Queries persistence layer
 *  - Returns alert if found
 *  - Returns 404 if alert does not exist
 * 
 * Failure handling:
 *  - Logs backend error
 *  - Returns generic failure response
 */
alertsRouter.get("/:id", async (req, res) => {
    try {
        // Extract alert identifier from URL path
        const id = req.params.id;

        /**
         * Basic input validation.
         * Prevents unnecessary database queries and undefined behavior.
         * UUID validation will be added in later phases
         */
        if (!id) {
            return res.status(400).json({ error: "Missing alert id"});
        }

        // Retrieve alert from service layer
        const alert = await getAlert(id);

        /**
         * Alert not found in database.
         * This is a normal condition, not a system error.
         */
        if (!alert) {
            return res.status(404).json({ error: "Alert not found" });
        }

        // Return alert details
        res.json(alert);

    } catch (err) {
        // Log internal failure for diagnostics
        logger.error("Failed to fetch alert", {
            error: err instanceof Error ? err.message : String(err),
            alert_id: req.params.id,
        });

        // Do not expose internal details to client
        res.status(500).json({ error: "Internal server error" });
    }
});
