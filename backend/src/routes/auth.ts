import { Router } from "express";

export const authRouter = Router();

/**
 * Pair mobile app with gateway
 * Placeholder until pairing logic is implemented
 */
authRouter.post("/pair", (req, res) => {
    res.json({
        status: "pairing not yet implemented"
    });
});