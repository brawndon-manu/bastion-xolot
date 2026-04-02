import { Router } from "express";
import { ensureDeviceExists } from "../services/device_service";
import { broadcast } from "../realtime/websocket";
import { processEvent } from "../services/correlation_service";

/**
 * Router responsible for ingesting raw events from external sources
 * 
 * Sources may include:
 *  - Network gateway (DNS logs, traffic data)
 *  - IDS system (e.g., Suricata)
 *  - Future agents and sensors
 * 
 * This is the ENTRY POINT of the security pipeline.
 */
export const eventsRouter = Router();

/**
 * Event ingestion endpoint
 * 
 * Endpoint:
 *  POST /events
 * 
 * Responsibilities:
 *  1. Validate incoming event
 *  2. Ensure device exists in database
 *  3. Pass event to correlation engine
 *  4. Broadcast result in real-time
 *  5. Return structured response
 */
eventsRouter.post("/", async (req, res) => {
    try {
        // Safely extract event payload
        const event = req.body ?? {};

        /**
         * Basic validation
         * 
         * Every event must include a type so it can be processed
         * by the correlation engine.
         */
        if (!event.type) {
            return res.status(400).json({ error: "Event type is required" });
        }

        /**
         * Ensure device exists (or create it if new)
         * 
         * This guarantees:
         *  - All events are tied to a known device
         *  - Device lifecycle is maintained automatically
         */
        const device = ensureDeviceExists({
            id: event.device_id,
            mac_address: event.mac_address,
            ip_address: event.ip,
            hostname: event.hostname
        });

        /**
         * Pass event to correlation engine
         * 
         * This is where:
         *  - Detection rules are applied
         *  - Risk score is updated
         *  - Alerts may be generated
         *  - Enforcement may be triggered
         */
        const result = await processEvent(event, device.id);

        /**
         * Broadcast event reception (real-time visibility)
         * 
         * NOTE:
         * result.event may be undefined unless explicitly returned
         * from correlation_service. This is typically used for:
         *  - Debugging
         *  - live dashboards
         */
        broadcast("event.received", result.event);

        /**
         * Return structured result to client
         * 
         * Example response may include:
         *  - alert (if generated)
         *  - enforcement action (if triggered)
         *  - updated device state
         */
        res.status(201).json(result);

    } catch (err) {
        console.error("Event ingestion failed:", err);
        res.status(500).json({ error: "Internal server error"});
    }
});