/**
 * Bastion Xolot Backend Configuration
 * 
 * This module centralizes all runtime configuration for the backend service.
 * Nothing else in the codebase should read process.env directly.
 * 
 * Goals:
 *  - Works on Raspberry Pi and developer machines
 *  - Safe defaults
 *  - Single source of truth
 *  - Easy to audit for security
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
 * Can be overriden for testing or container deployment.
 */
const API_PORT = parseInt(process.env.API_PORT || "3000", 10);

/**
 * Secret used for signing authentication tokens
 * 
 * IMPORTANT:
 * In production this MUST be set via environment variable.
 * Never hardcode secrets in source code 
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
export const config = Object.freeze({
    NODE_ENV,
    DB_PATH,
    API_PORT,
    AUTH_SECRET,
});