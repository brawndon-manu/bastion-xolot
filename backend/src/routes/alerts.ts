import { Router } from "express";
import { listAlerts, getAlert } from "../services/alert_service";

export const alertsRouter = Router();

/**
 * Get all alerts
 */
alertsRouter.get("/", async (req, res) => {
    const alerts = await listAlerts();
    res.json(alerts);
});

/**
 * Get alert details
 */
alertsRouter.get("/:id", async (req, res) => {
    const alert = await getAlert(req.params.id);

    if (!alert) {
        return res.status(404).json({ error: "Alert not found" });
    }

    res.json(alert);
});