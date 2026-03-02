import { Router } from "express";
import { createAlert } from "../services/alert_service";
import { ensureDeviceExists } from "../services/device_service";
import { broadcast } from "../realtime/websocket";
import { explainSecurityEvent } from "../services/plain_english";
import { processEvent } from "../services/correlation_service";

export const eventsRouter = Router();

/**
 * Event ingestion endpoint
 * Used for testing, not complete implementation
 */
eventsRouter.post("/", async (req, res) => {
    try {
        const event = req.body;

        console.log("Received event:", event);

        // Ensure device exists BEFORE creating alert
        const device = ensureDeviceExists({
            id: event.device_id,
            ip_address: event.ip,
            hostname: event.hostname
        });

        const alert = await processEvent(event, device.id);

        if (alert) {
            broadcast("alert_created", alert);
        }

        res.status(201).json({
            status: "processed",
            alert
        });

    } catch (err) {
        console.error("Event ingestion failed:", err);
        res.status(500).json({ error: "Internal server error"});
    }
});