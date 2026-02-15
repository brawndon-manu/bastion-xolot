import { Router } from "express";
import { quarantineDevice, releaseDevice } from "../services/enforcement_service";

export const enforcementRouter = Router();

/**
 * Quaratine a device
 */
enforcementRouter.post("/quaratine/:deviceId", async (req, res) => {
    await quarantineDevice(req.params.deviceId);
    res.json({ status: "device quarantined "});
});

/**
 * Release a device from quarantine
 */
enforcementRouter.post("/release/:deviceId", async (req, res) => {
    await releaseDevice(req.params.deviceId);
    res.json({ status: "device released "});
})