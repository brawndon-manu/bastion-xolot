import express from "express";
import http from "http";
import { getRealtimeStatus, initWebSocket } from "./realtime/websocket";
import { config } from "./config";

import { eventsRouter } from "./routes/events";
import { alertsRouter } from "./routes/alerts";

import { getDb, initDatabase } from "./db/db";

import { devicesRouter } from "./routes/devices";

import { enforcementRouter } from "./routes/enforcement";

/**
 * ==============================
 * DATABASE INITIALIZATION
 * ==============================
 * 
 * Initialize database BEFORE starting server.
 * Ensures:
 *  - Database file exists
 *  - Schema is loaded
 *  - Migrations are applied
 * 
 * This guarantees the backend is fully operational at startup.
 */
initDatabase();

/**
 * ==============================
 * EXPRESS APPLICATION SETUP
 * ==============================
 */
const app = express();

/**
 * Enable JSON request parsing
 * 
 * Required for:
 *  - POST /events
 *  - POST /enforcement
 *  - Any API receiving JSON payloads
 */
app.use(express.json());

/**
 * ==============================
 * ROUTE REGISTRATION
 * ==============================
 * 
 * Each route represents a layer of the system:
 * /devices     -> Device inventory & state
 * /enforcement -> Response / control actions
 * /events      -> Event ingestion (entry point)
 * /alerts      -> Detection output
 */
app.use("/devices", devicesRouter);
app.use("/enforcement", enforcementRouter);
app.use("/events", eventsRouter);
app.use("/alerts", alertsRouter);

/**
 * ==============================
 * GLOBAL ERROR HANDLER
 * ==============================
 * 
 * Catches unhandled errors from any route.
 * Prevents:
 *  - Server crashes
 *  - Leaking internal error details
 * 
 * NOTE: This should be the LAST middleware
 */
app.use((err: any, req: any, res: any, next: any) => {
    console.error("Unhandle server error:", err);
    res.status(500).json({ error: "Internal server error" });
}); 

/**
 * ==============================
 * HEALTH CHECK ENDPOINT
 * ==============================
 * 
 * Endpoint:
 *  GET /health
 * 
 * Used for:
 *  - Monitoring system status
 *  - Debugging
 *  - Deployment verification
 * 
 * Returns:
 *  - API status
 *  - Database connectivity
 *  - WebSocket status
 *  - Configuration flags
 */
app.get("/health", (req, res) => {
    const db = getDb();

    // Simple DB check query
    const dbCheck = db.prepare("SELECT 1 as ok").get() as { ok: number };
    res.json({
        status: "ok",
        service: "bastion-backend",
        environment: config.NODE_ENV,

        /**
         * Security configuration flags
         */
        monitor_only: config.MONITOR_ONLY,
        auto_quarantine_threshold: config.AUTO_QUARANTINE_THRESHOLD,

        /**
         * System health indicators
         */
        database: dbCheck.ok === 1 ? "ok" : "degraded",
        realtime: getRealtimeStatus(),

        /**
         * Timestamp for debugging / monitoring
         */
        time: new Date().toISOString(),
    });
});

/**
 * ==============================
 * HTTP SERVER + WEBSOCKET SETUP
 * ==============================
 * 
 * Create HTTP server from Express app
 * This allows WebSocket to share the same port.
 */
const server = http.createServer(app);

/**
 * Initialize WebSocket server
 * 
 * Enables:
 *  - Real-time alert streaming
 *  - Live device updates
 *  - Instant enforcement notifications
 */
initWebSocket(server);

/**
 * ==============================
 * SERVER STARTUP
 * ==============================
 * 
 * Start listening on configured port.
 * Logs key system information for visibility.
 */
server.listen(config.API_PORT, () => {
    console.log("=====================================");
    console.log(`Running in: ${config.NODE_ENV}`);
    console.log(`Database path: ${config.DB_PATH}`);
    console.log(`API port: ${config.API_PORT}`);
    console.log("=====================================");
});