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
 *  - Ensure database directory exists
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

    /**
     * Enable Write-Ahead Logging (WAL)
     * 
     * Benefits:
     *  - Better performance for concurrent reads/writes
     *  - Reduced risk of corruption on crash
     */
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
 * Loads the base schema from schema.sql
 * 
 * This creates tables if they do not exist.
 * Safe to run multiple times due to IF NOT EXISTS usage.
 */
function initializeSchema() {
    const schemaPath = path.join(__dirname, "schema.sql");

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
 *  - Ignores "duplicate column" erros (already applied)
 *  - Throws for any other unexpected error
 * 
 * This allows safe repeated startups without breaking the DB
 */
function applyMigrations() {
    const migrations = [
        "ALTER TABLE enforcement_actions ADD COLUMN mode TEXT DEFAULT 'active'",
        "ALTER TABLE enforcement_actions ADD COLUMN status TEXT DEFAULT 'applied'",
        "ALTER TABLE enforcement_actions ADD COLUMN evidence TEXT",
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
 * 
 * Centralizing DB access allows:
 *  - Future logging of queries
 *  - performance monitoring
 *  - easier refactoring if DB changes
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
 * Excutes a query returning multiple rows
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
 *  - Keeping security state consistent
 *  - preventing partial writes (e.g., alert created but device not updated)
 * 
 * Example:
 * transaction(() => {
 *  run("INSERT INTO events ...")
 *  run("UPDATE devices ...")
 *  run("INSERT INTO alerts ...")
 * })
 */
export function transaction<T>(fn: () => T): T {
    return getDb().transaction(fn)();
}