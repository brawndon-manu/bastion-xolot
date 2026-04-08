import { Router } from "express";

export const healthRouter = Router();

/**
 * Health endpoint
 * Used by:
 *  - mobile app
 *  - deployment scripts
 *  - monitoring
 */
healthRouter.get("/", (req, res) => {
    res.json({
        status: "ok",
        service: "bastion-backend",
        time: new Date().toISOString()
    });
});