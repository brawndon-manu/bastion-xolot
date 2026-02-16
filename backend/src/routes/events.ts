import { Router } from "express";
import { createAlert } from "../services/alert_service";
// import { processIncomingEvent } from "../services/correlation_service";

export const eventsRouter = Router();

/**
 * Ingest event from gateway agent
 * This is the primary signal entry point of the system.
 *
eventsRouter.post("/", async (req, res) => {
    try {
        const event = req.body;

        if (!event) {
            return res.status(400).json({ error: "Missing event payload" });
        }

        const result = await processIncomingEvent(event);

        res.json({
            status: "accepted",
            correlationId: result.correlationId || null
        });
    } catch (error) {
        console.error("Event ingestion error:", error);
        res.status(500).json({ error: "Failed to process event" })
    }
});

*/

/**
 * Event ingestion endpoint
 * Used for testing, not complete implementation
 */
eventsRouter.post("/", async (req, res) => {
    try {
        const event = req.body;

        console.log("Received event:", event);

        // Temp test: create an alert from incoming event
        await createAlert({
            device_id: "test-device",
            severity: "medium",
            title: "Blocked suspicious domain",
            explanation: "Device attempted to contact known malicious domain",
            evidence: JSON.stringify(event),
            confidence: 0.75,
            type: ""
        });

        res.json({ status: "event processed" });

    } catch (err) {
        console.error("Event ingestion failed:", err);
        res.status(500).json({ error: "Internal server error"});
    }
});