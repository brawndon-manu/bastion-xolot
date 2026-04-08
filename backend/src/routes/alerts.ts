import { Router } from "express";
import { listAlerts, getAlert } from "../services/alert_service";

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

/**
 * GET /alerts
 * 
 * Returns all alerts stored in the system.
 * 
 * Behavior:
 *  - Retrieves alerts from persistence layer
 *  - Returns alerts ordered by service implemenation
 *  - Never exposes interal errors to client
 * 
 * Failure handling:
 *  - Logs error for backend diagnostics
 *  - Returns HTTP 500 without leaking system details
 */
alertsRouter.get("/", async (req, res) => {
    try {
        // Request alert list from service layer
        const alerts = await listAlerts();

        // Send alerts as JSON response
        res.json(alerts);

    } catch (err) {
        // Log internal failure for debugging and audit visibility
        console.error("Failed to fetch alerts:", err);

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
        console.error("Failed to fetch alert:", err);

        // Do not expose internal details to client
        res.status(500).json({ error: "Internal server error" });
    }
});