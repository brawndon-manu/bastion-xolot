import Database from "better-sqlite3";
import fs from "fs";
import path from "path";
import { config } from "../config";

let db: Database.Database;

/**
 * Initializes the database connection
 * 
 * This function must run exactly once at backend startup
 * It guarantees:
 *  - database file exists
 *  - directory exists
 *  - schema exists
 *  - reliability settings are applied
 * 
 * In a deployable security appliance, the system must recover
 * automatically after reboot - no manual setup allowed
 */
export function initDatabase() {
    // Path where SQLite database file will be stored
    const dbPath = config.DB_PATH;

    // Extract directory path from database file path
    const dir = path.dirname(dbPath);
    
    // Ensure database directory exists
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, {recursive: true});
    }

    // Open or create the SQLite database file
    db = new Database(dbPath);

    // Write-Ahead Logging - prevents corruption during crashes or power loss
    db.pragma("journal_mode = WAL");

    // Normal sync - balanced durability vs performance for appliance workloads
    db.pragma("foreign_keys = ON");

    // Ensure schema exists before backend starts serving requests
    initializeSchema(); 
}

/**
 * Loads and executers SQL schema file
 * 
 * This guarantees the database structure exists on every startup
 * If tables alraedy exist -> SQLite ignores CREATE statements
 * 
 * Makes Bastion Xolot plug-and-play
 */
function initializeSchema() {
    // Resolve path to schema.sql located in same directory
    const schemaPath = path.join(__dirname, "schema.sql");

    // Read schema file as text
    const schema = fs.readFileSync(schemaPath, "utf-8");

    // Excure SQL statements
    db.exec(schema);
}

/**
 * Returns active database connection
 * 
 * Safety check prevents usage before initialization
 * If backend tries to access DB before initDatabase(),
 * that is a critical error
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
 * Used by services to modify persistent state
 * Example:
 * run("INSERT INTO devices VALUES (?, ?)", [id, mac])
 * 
 * Centralizing DB access allows:
 *  - logging queries later
 *  - metrics collection
 *  - swapping database implementation if needed
 */
export function run(query: string, params: any[] = []) {
    return getDb().prepare(query).run(params);
}

/**
 * Excutes query returning a single row
 * 
 * Used when fetching one device, alert, or record
 * Returns undefined if no result exists
 */
export function get(query: string, params: any[] = []) {
    return getDb().prepare(query).get(params);
}

/**
 * Executes query returning multiple rows
 * 
 * Used for:
 *  - device lists
 *  - alert history
 *  - event queries
 */
export function all(query: string, params: any[] = []) {
    return getDb().prepare(query).all(params);
}

/**
 * Executes multiple database operations automically
 * 
 * If any operation fails -> all changes are rolled back
 * 
 * This is critical for Bastion Xolot:
 *  - events, device updates, and alerts must stay consistent
 *  - partial writes could create false security state
 * 
 * Example usage:
 * 
 * transaction(() => {
 *  run("INSERT INTO events ...")
 *  run("UPDATE devices ...")
 *  run("INSERT INTO alerts ...")
 * })
 */
export function transaction<T>(fn: () => T): T {
    return getDb().transaction(fn)();
}