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
 * ===============================
 * DATABASE INITIALIZATION
 * ===============================
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
app.disable("x-powered-by");

/**
 * Enable JSON request parsing
 * 
 * Required for:
 *  - POST /events
 *  - POST /enforcement
 *  - Any API receiving JSON payloads
 */
app.use(express.json({ limit: "256kb" }));

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
 */
app.get("/health", (req, res) => {

    // Get database instance/connection
    const db = getDb();

    // Perform a simple query to verify database connectivity
    // "SELECT 1" is a lightweight way to check if DB is responsive
    const dbCheck = db.prepare("SELECT 1 as ok").get() as { ok: number };

    // Return overall system health information
    res.json({
        status: "ok",                                                   // Indicates the service is running
        service: "bastion-backend",                                     // Name of the service (useful for monitoring tools)
        environment: config.NODE_ENV,                                   // Current environment (development, production, etc.)
        monitor_only: config.MONITOR_ONLY,                              // Whether the system is in passive monitoring mode (no enforcement actions)
        auto_quarantine_threshold: config.AUTO_QUARANTINE_THRESHOLD,    // Threshold value used to trigger automatic quarantine actions
        database: dbCheck.ok === 1 ? "ok" : "degraded",                 // Reports database health based on query result
        realtime: getRealtimeStatus(),                                  // Status of real-time system (e.g., WebSocket connections)
        time: new Date().toISOString(),                                 // Current server time (useful for debugging and monitoring)
    });
});

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
app.use((req, res) => {
    res.status(404).json({ error: `Route not found: ${req.method} ${req.originalUrl}` });
});

app.use((err: any, req: any, res: any, next: any) => {
    console.error("Unhandled server error:", err);

    if (err?.type === "entity.too.large") {
        return res.status(413).json({ error: "Request body exceeds size limit" });
    }

    if (err instanceof SyntaxError && "body" in err) {
        return res.status(400).json({ error: "Malformed JSON request body" });
    }

    res.status(500).json({ error: "Internal server error" });
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