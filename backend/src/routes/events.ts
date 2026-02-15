import { Router } from "express";
import { processIncomingEvent } from "../services/correlation_service";

export const eventsRouter = Router();

/**
 * Ingest event from gateway agent
 * This is the primary signal entry point of the system.
 */
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