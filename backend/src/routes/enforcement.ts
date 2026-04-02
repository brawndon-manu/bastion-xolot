import { Router } from "express";
import { 
    quarantineDevice, 
    unquarantineDevice,
    listEnforcementActions
 } from "../services/enforcement_service";

 /**
  * Router responsible for enforcement-related actions
  * 
  * Handles:
  *  - Quarantining devices
  *  - Releasing devices from quarantine
  *  - Viewing enforcement history
  */
export const enforcementRouter = Router();

/**
 * Shared handler for quarantining a device
 * 
 * Extracted to support:
 *  - Multiple route aliases (e.g., typo tolerance)
 *  - Cleaner route definitions
 * 
 * Responsibilities:
 *  - Validate request data
 *  - Call enforcement service
 *  - Return structured response
 */
async function handleQuarantine(req: any, res: any) {
    try {
        const action = quarantineDevice(
            req.params.id,                                                              // Target device ID
            req.body.reason || "policy_violation",                                      // Reason for enforcement
            {
                initiated_by: req.body.initiated_by || "operator",                      // Who triggered action
                evidence: req.body.evidence ? JSON.stringify(req.body.evidence) : null, // Optional supporting evidence
            }
        );

        // Return created enforcement record
        res.status(201).json(action);

    } catch (err) {
        console.error("Quarantine failed:", err);
        res.status(500).json({ error: err instanceof Error ? err.message : "Internal server error" });
    }
}

/**
 * Quarantine endpoints
 * 
 * Primary route:
 *  POST /enforcement/quarantine/:id
 * 
 * Secondary route (typo-safe alias):
 *  POST /enforcement/quarantine/:id
 * 
 * The alias ensures the API is forgiving during testing/demo.
 */
enforcementRouter.post("/quarantine/:id", handleQuarantine);
enforcementRouter.post("/quaratine/:id", handleQuarantine);

/**
 * Release device from quarantine
 * 
 * Endpoint:
 *  POST /enforcement/release/:id
 * 
 * Behavior:
 *  - Updates device status back to "normal"
 *  - Logs enforcement action (unquarantine)
 *  - Optionally records operator + evidence
 */
enforcementRouter.post("/release/:id", async (req, res) => {
    try {
        const action = unquarantineDevice(req.params.id, {
            initiated_by: req.body.initiated_by || "operator",
            evidence: req.body.evidence ? JSON.stringify(req.body.evidence) : null,
        });
        res.status(200).json(action);
    } catch (err) {
        console.error("Release failed:", err);
        res.status(500).json({ error: err instanceof Error ? err.message : "Internal server error" });
    }
});

/**
 * Retrieve enforcement history
 * 
 * Endpoint:
 *  GET /enforcement/history
 * 
 * Returns:
 *  - List of all enforcement actions (quarantine/unquarantine)
 *  - Ordered by most recent first (handled in service)
 * 
 * Used for:
 *  - Auditing
 *  - Debugging
 *  - UI display
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