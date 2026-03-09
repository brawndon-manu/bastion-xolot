import { Router } from "express";
import { 
    quarantineDevice, 
    unquarantineDevice,
    listEnforcementActions
 } from "../services/enforcement_service";

export const enforcementRouter = Router();

/**
 * Quaratine a device
 */
enforcementRouter.post("/quaratine/:id", async (req, res) => {
    try {
        const action = quarantineDevice(
            req.params.id,
            req.body.reason || "policy_violation"
        );

        res.status(201).json(action);
    } catch (err) {
        console.error("Quarantine failed:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});

/**
 * Release a device from quarantine
 */
enforcementRouter.post("/release/:id", async (req, res) => {
    try {
        const action = unquarantineDevice(req.params.id);
        res.status(200).json(action);
    } catch (err) {
        console.error("Release failed:", err);
        res.status(500).json({ error: "Internal server error" });
    }
});

/**
 * Enforcement history
 */
enforcementRouter.get("/history", (req, res) => {
    try {
        const history = listEnforcementActions();
        res.json(history);
    } catch (err) {
        console.error("Failed to fetch enforcement history:", err);
        res.status(500).json({error: "Internal server error" });
    }
});