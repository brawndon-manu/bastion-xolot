import { Router } from "express";
import { listDevices, getDevice } from "../services/device_service";

export const devicesRouter = Router();

/**
 * List all known devices
 */
devicesRouter.get("/", async (req, res) => {
    const devices = await listDevices();
    res.json(devices);
});

/**
 * Get single device by ID
 */
devicesRouter.get("/:id", async (req, res) => {
    const device = await getDevice(req.params.id);

    if (!device) {
        return res.status(404).json({ error: "Device not found" });
    }

    res.json(device);
})