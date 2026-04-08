import { Router } from "express";
import { getConsistencyReport, getHealthSnapshot } from "../services/consistency_service";
import { logger } from "../utils/logger";

export const healthRouter = Router();

/**
 * Health endpoint
 * Used by:
 *  - mobile app
 *  - deployment scripts
 *  - monitoring
 */
healthRouter.get("/", (req, res) => {
    try {
        res.json(getHealthSnapshot());
    } catch (err) {
        logger.error("Failed to build health snapshot", {
            error: err instanceof Error ? err.message : String(err),
        });
        res.status(500).json({ error: "Internal server error" });
    }
});

/**
 * Consistency endpoint
 * 
 * Used during demos and operator troubleshooting to quickly spot
 * common backend state issues that are otherwise hard to notice.
 */
healthRouter.get("/consistency", (req, res) => {
    try {
        res.json(getConsistencyReport());
    } catch (err) {
        logger.error("Failed to build consistency report", {
            error: err instanceof Error ? err.message : String(err),
        });
        res.status(500).json({ error: "Internal server error" });
    }
});
