import { Router } from "express";
import { listDevices, getDevice } from "../services/device_service";

export const devicesRouter = Router();

/**
 * List all known devices
 */
devicesRouter.get("/", async (req, res) => {
    try {
        const devices = listDevices();
        res.json(devices);
    } catch (err) {
        console.error("Failed to fetch devices:", err);
        res.status(500).json({ error: "Internal server error"});
    }
});

/**
 * Get single device by ID
 */
devicesRouter.get("/:id", async (req, res) => {
    try {
        const device = getDevice(req.params.id);

        if (!device) {
            return res.status(404).json({ error: "Device not found" });
        }

        res.json(device);
    } catch (err) {
        console.error("Failed to fetch device:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});