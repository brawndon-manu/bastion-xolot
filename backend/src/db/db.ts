import Database from "better-sqlite3";
import fs from "fs";
import path from "path";
import { config } from "../config";

/**
 * Singleton database instance
 * 
 * This will be initialized once at application startup.
 * All services access the database through helper functions
 * (getDb, run, get, all) to enforce consistent usage.
 */
export let db: Database.Database;

/**
 * Initializes the SQLite database
 * 
 * Responsibilites:
 *  - Ensure datbase directory exists
 *  - Open/create database file
 *  - Apply performance and integrity settings
 *  - Load base schema
 *  - Apply migrations safely
 * 
 * This function MUST be called before any database usage.
 */
export function initDatabase() {
    const dbPath = config.DB_PATH;

    // Ensure directory exists (important for first-time startup)
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }

    // Open SQLite database (creates file if it doesn't exist)
    db = new Database(dbPath);

    // Enable Write-Ahead Logging (WAL)
    db.pragma("journal_mode = WAL");

    /**
     * Enforce foreign key constraints
     * 
     * Ensures:
     *  - alerts must reference valid devices
     *  - enforcement actions must reference valid devices
     */
    db.pragma("foreign_keys = ON");

    // Load base schema (tables)
    initializeSchema();

    // Apply incremental schema updates (safe upgrades)
    applyMigrations();
}

/**
 * Resolves the absolute path to schema.sql
 * 
 * Why this exists:
 * The location of schema.sql differs depending on how the backend is run:
 * 
 *  - Development (ts-node):
 *      schema is typically in src/db/schema.sql
 * 
 *  - Production build (compiled JS in /dist):
 *      schema may be copied to dist/db/schema.sql
 * 
 *  - Runtime (__dirname-based resolution):
 *      schema may exist relative to compiled file location
 * 
 * This function checks multiple possible locations and returns
 * the first valid path that exists on disk.
 * 
 * This ensures the backend works reliably across:
 *  - local development
 *  - compiled builds
 *  - deployment environments
 */
function resolveSchemaPath(): string {
    /**
     * Candidate paths to check (in priority order)
     */
    const candidates = [
        // Same directory as compiled file (most reliable in production)
        path.join(__dirname, "schema.sql"),

        // Compiled project structure (dist folder)
        path.join(process.cwd(), "dist/db/schema.sql"),

        // Source project structure (development mode)
        path.join(process.cwd(), "src/db/schema.sql"),
    ];

    // Iterate through candidates and return the first valid file
    for (const candidate of candidates) {
        if (fs.existsSync(candidate)) {
            return candidate;
        }
    }

    // If no valid path is found, throw an error
    throw new Error(`Unable to locate schema.sql. Checked: ${candidates.join(", ")}`);
}

/**
 * Loads the base schema from schema.sql
 * 
 * This creates tables if they do not exist.
 */
function initializeSchema() {
    const schemaPath = resolveSchemaPath();

    // Read schema file from disk
    const schema = fs.readFileSync(schemaPath, "utf-8");

    // Execute SQL statements
    db.exec(schema);
}

/**
 * Applies database migrations
 * 
 * Used to evolve schema over time without losing data.
 * 
 * Behavior:
 *  - Runs ALTER TABLE statements
 *  - Ignores "duplicate column" errors (already applied)
 *  - Throws for any other unexpected error
 * 
 * This allows safe repeated startups without breaking the DB.
 */
function applyMigrations() {
    const migrations = [
        "ALTER TABLE enforcement_actions ADD COLUMN mode TEXT DEFAULT 'active'",
        "ALTER TABLE enforcement_actions ADD COLUMN status TEXT DEFAULT 'applied'",
        "ALTER TABLE enforcement_actions ADD COLUMN evidence TEXT",
        "ALTER TABLE alerts ADD COLUMN fingerprint TEXT",
        "ALTER TABLE alerts ADD COLUMN updated_at INTEGER",
        "ALTER TABLE alerts ADD COLUMN resolved_at INTEGER",
        "ALTER TABLE anomalies ADD COLUMN updated_at INTEGER",
        "ALTER TABLE anomalies ADD COLUMN resolved_at INTEGER",
        "ALTER TABLE devices ADD COLUMN vendor TEXT",
    ];

    for (const migration of migrations) {
        try {
            db.exec(migration);
        } catch (error) {
            const message = error instanceof Error ? error.message : String(error);

            // Ignore if column already exists (migration already applied)
            if (!message.includes("duplicate column name")) {
                throw error;
            }
        }
    }

    // Backfill timestamps for older rows created before lifecycle columns existed.
    db.exec(`
        UPDATE alerts
        SET updated_at = COALESCE(updated_at, created_at),
            resolved_at = CASE WHEN status = 'resolved' THEN COALESCE(resolved_at, updated_at, created_at) ELSE resolved_at END
    `);

    db.exec(`
        UPDATE anomalies
        SET updated_at = COALESCE(updated_at, created_at),
            resolved_at = CASE WHEN status = 'resolved' THEN COALESCE(resolved_at, updated_at, created_at) ELSE resolved_at END
    `);

    // Clamp legacy rows created before backend risk scores were bounded.
    db.exec(`
        UPDATE devices
        SET risk_score = MIN(MAX(COALESCE(risk_score, 0), 0), 100)
    `);

    // Reclassify noisy IDS signatures that older code stored as high severity.
    db.exec(`
        UPDATE alerts
        SET severity = 'low',
            confidence = MIN(COALESCE(confidence, 0.45), 0.45),
            updated_at = COALESCE(updated_at, created_at)
        WHERE type = 'ids_alert'
          AND LOWER(COALESCE(severity, '')) = 'high'
          AND (
              LOWER(COALESCE(title, '')) LIKE '%suricata stream%'
              OR LOWER(COALESCE(title, '')) LIKE '%et info %'
              OR LOWER(COALESCE(title, '')) LIKE '%observed %'
          )
    `);
}

/**
 * Returns the active database instance
 * 
 * Throws an error if the database has not been initialized.
 * This prevents accidental usage before initDatabase() runs.
 */
export function getDb() {
    if (!db) {
        throw new Error("Database not initialized");
    }
    return db;
}

/**
 * Executes a write operation (INSERT, UPDATE, DELETE)
 * 
 * Example usage:
 * run("INSERT INTO devices VALUES (?, ?)", [id, mac])
 */
export function run(query: string, params: any[] = []) {
    return getDb().prepare(query).run(params);
}

/**
 * Executes a query returning a single row
 * 
 * Used for:
 *  - fetching one device
 *  - fetching one alert
 * 
 * Returns:
 *  - object if found
 *  - undefined if not found
 */
export function get(query: string, params: any[] = []) {
    return getDb().prepare(query).get(params);
}

/**
 * Executes a query returning multiple rows
 * 
 * Used for:
 *  - listing devices
 *  - listing alerts
 *  - fetching history data
 */
export function all(query: string, params: any[] = []) {
    return getDb().prepare(query).all(params);
}

/**
 * Executes multiple operations atomically
 * 
 * If any operation fails -> ALL changes are rolled back
 * 
 * Critical for:
 *  - keeping security state consistent
 *  - preventing partial writes (e.g., alert created but device not updated)
 * 
 * Example:
 * transaction(() => {
 *   run("INSERT INTO events ...")
 *   run("UPDATE devices ...")
 *   run("INSERT INTO alerts ...")
 * })
 */
export function transaction<T>(fn: () => T): T {
    return getDb().transaction(fn)();
}
