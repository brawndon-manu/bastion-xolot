/**
 * Bastion Xolot Backend Configuration
 * 
 * This module centralizes all runtime configuration for the backend service.
 * Nothing else in the codebase should read process.env directly.
 * 
 */

import path from "path";

/**
 * Determine runtime environment
 * 
 * NODE_ENV values:
 *  - "production" -> Raspberry Pi deployment
 *  - "development" -> Local dev machine
 */
const NODE_ENV = process.env.NODE_ENV || "development";

/**
 * Determine database file path
 * 
 * Production appliance:
 *  /var/lib/bastion-xolot/bastion.db
 *  -> persistent storage Location on Linux systems
 * 
 * Development:
 *  backend/data/bastion.db
 *  -> local project folder for convenience
 */
const DB_PATH = 
    process.env.DB_PATH ||
    (NODE_ENV === "production"
        ? "/var/lib/bastion-xolot/bastion.db"
        : path.join(__dirname, "../../data/bastion.db")
    );

/**
 * HTTP server port.
 * 
 * Default: 3000
 */
const API_PORT = parseInt(process.env.API_PORT || "3000", 10);
const MONITOR_ONLY = process.env.MONITOR_ONLY !== "false";
const AUTO_QUARANTINE_THRESHOLD = parseInt(
    process.env.AUTO_QUARANTINE_THRESHOLD || "50",
    10
);

/**
 * Secret used for signing authentication tokens 
 */
const AUTH_SECRET = 
    process.env.AUTH_SECRET ||
    (NODE_ENV === "development" ? "dev-secret-change-me" : undefined);

/**
 * Validate critical configuration
 * 
 * In production mode, certain values must exist.
 * If missing -> fail fast and stop service.
 * This prevents insecure deployments.
 */
if (NODE_ENV === "production") {
    if (!AUTH_SECRET) {
        throw new Error("AUTH_SECRET must be set in production environment");
    }
}

/**
 * Export frozen configuration object
 * 
 * Object.freeze prevents accidental mutation at runtime
 * This is important for deterministic appliance behavior
 */
// Deduplication window for alerts (default: 30 minutes)
const ALERT_DEDUP_WINDOW_MS = parseInt(
    process.env.ALERT_DEDUP_WINDOW_MS || "1800000",
    10
);

// Window for resolving open anomalies (default: 10 minutes)
const ANOMALY_RESOLUTION_WINDOW_MS = parseInt(
    process.env.ANOMALY_RESOLUTION_WINDOW_MS || "600000",
    10
);

const DESIRED_STATE_PATH = process.env.DESIRED_STATE_PATH ||
    "/var/lib/bastion/enforcement/desired_state.json";

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || undefined;

export const config = Object.freeze({
    NODE_ENV,
    DB_PATH,
    API_PORT,
    MONITOR_ONLY,
    AUTO_QUARANTINE_THRESHOLD,
    AUTH_SECRET,
    ALERT_DEDUP_WINDOW_MS,
    ANOMALY_RESOLUTION_WINDOW_MS,
    DESIRED_STATE_PATH,
    ANTHROPIC_API_KEY,
});