import { Router } from "express";
import { ensureDeviceExists } from "../services/device_service";
import { broadcast } from "../realtime/websocket";
import { processEvent } from "../services/correlation_service";

export const eventsRouter = Router();

/**
 * Event ingestion endpoint
 * Used for testing, not complete implementation
 */
eventsRouter.post("/", async (req, res) => {
    try {
        const event = req.body;

        const device = ensureDeviceExists({
            id: event.device_id,
            ip_address: event.ip,
            hostname: event.hostname
        });

        const result = await processEvent(event, device.id);

        if (result.alert) {
            broadcast("alert", result.alert);
        }

        res.status(201).json(result);

    } catch (err) {
        console.error("Event ingestion failed:", err);
        res.status(500).json({ error: "Internal server error"});
    }
});