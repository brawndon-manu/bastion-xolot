import express from "express";
import http from "http";
import { initWebSocket } from "./realtime/websocket";
import { config } from "./config";

import { eventsRouter } from "./routes/events";
import { alertsRouter } from "./routes/alerts";
import { healthRouter } from "./routes/health";

import { initDatabase } from "./db/db";

import { devicesRouter } from "./routes/devices";

import { enforcementRouter } from "./routes/enforcement";
import { logger } from "./utils/logger";

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
 * /health      -> Health and diagnostics
 */
app.use("/devices", devicesRouter);
app.use("/enforcement", enforcementRouter);
app.use("/events", eventsRouter);
app.use("/alerts", alertsRouter);
app.use("/health", healthRouter);

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
    logger.warn("Route not found", {
        method: req.method,
        url: req.originalUrl,
    });

    res.status(404).json({ error: `Route not found: ${req.method} ${req.originalUrl}` });
});

app.use((err: any, req: any, res: any, next: any) => {
    logger.error("Unhandled server error", {
        method: req?.method,
        url: req?.originalUrl,
        error: err instanceof Error ? err.message : String(err),
    });

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
    logger.info("Bastion backend started", {
        environment: config.NODE_ENV,
        database_path: config.DB_PATH,
        api_port: config.API_PORT,
        monitor_only: config.MONITOR_ONLY,
        auto_quarantine_threshold: config.AUTO_QUARANTINE_THRESHOLD,
        alert_dedup_window_ms: config.ALERT_DEDUP_WINDOW_MS,
        anomaly_resolution_window_ms: config.ANOMALY_RESOLUTION_WINDOW_MS,
        resolved_anomaly_risk_decay: config.RESOLVED_ANOMALY_RISK_DECAY,
    });
});
