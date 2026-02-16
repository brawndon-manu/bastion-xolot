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

initDatabase();
const app = express();
app.use(express.json());

/**
 * Register API Routes
 * These map URL paths -> route modules
 */
app.use("/events", eventsRouter);
app.use("/alerts", alertsRouter);

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
    console.log(`Running in: ${config.NODE_ENV}`);
    console.log(`Database path: ${config.DB_PATH}`);
    console.log(`API port: ${config.API_PORT}`);
    console.log("Realtime WebSocket ready");
})