/**import { config } from "./config";

console.log("Running in:", config.NODE_ENV);
console.log("Database path:", config.DB_PATH);
console.log("API port:", config.API_PORT);

Previos test code
*/

import express from "express";
import http from "http";
import { initWebSocket } from "./realtime/websocket";
import { config } from "./config";

import { eventsRouter } from "./routes/events";
import { alertsRouter } from "./routes/alerts";

import { initDatabase } from "./db/db";

import { devicesRouter } from "./routes/devices";

import { enforcementRouter } from "./routes/enforcement";

initDatabase();
const app = express();
app.use(express.json());
app.use("/devices", devicesRouter);

app.use("/enforcement", enforcementRouter);

/**
 * Register API Routes
 * These map URL paths -> route modules
 */
app.use("/events", eventsRouter);
app.use("/alerts", alertsRouter);

/**
 * Global error handler
 * Prevents backened crash and returns structured error
 */
app.use((err: any, req: any, res: any, next: any) => {
    console.error("Unhandle server error:", err);
    res.status(500).json({ error: "Internal server error" });
}); 

/**
 * Health check endpoint
 */
app.get("/health", (req, res) => {
    res.json({ status: "ok"});
});

// Create HTTP server from express
const server = http.createServer(app);

// Attach WebSocket to same server
initWebSocket(server);

// Start listening on configured port
server.listen(config.API_PORT, () => {
    console.log("=====================================");
    console.log(`Running in: ${config.NODE_ENV}`);
    console.log(`Database path: ${config.DB_PATH}`);
    console.log(`API port: ${config.API_PORT}`);
    console.log("=====================================");
})