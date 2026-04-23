import { Router } from "express";
import { listDevices, getDevice, updateDeviceRole } from "../services/device_service";

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

/**
 * Update device role
 */
devicesRouter.patch("/:id", async (req, res) => {
    try {
        const { role } = req.body;
        if (!role) {
            return res.status(400).json({ error: "role is required" });
        }
        const device = updateDeviceRole(req.params.id, role);
        if (!device) {
            return res.status(404).json({ error: "Device not found or invalid role" });
        }
        res.json(device);
    } catch (err) {
        console.error("Failed to update device role:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});