import { getDb } from "../db/db";
import { randomUUID } from "crypto";

/**
 * Represents a persisted alert record in the database
 * 
 * This is the canonical alert structure used across:
 *  - correlation_service (creation)
 *  - alerts API (retrieval)
 *  - frontend / mobile app (display)
 */
export type AlertRecord = {
    id: string;                     // Unique alert identifier
    device_id: string | null;       // Associated device (if known)
    type: string;                   // Alert type (e.g., dns_block, ids_alert)
    severity: string;               // Severity level (low, medium, hight)
    title: string;                  // Short summary of the alert
    explanation: string | null;     // Human-readable explanation
    evidence: string | null;        // Raw evidence (JSON string)
    confidence: number | null;      // Confidence score (0-1)
    status: string;                 // Alert state (active, resolved, etc.)
    created_at: number;             // Timestamp (ms since epoch)
};

/**
 * Creates and persists a new alert
 * 
 * Responsibilites:
 *  - Normalize input data
 *  - Generate unique ID
 *  - State alert in database
 *  - Return structured alert object
 * 
 * Called by:
 *  - correlation_service (primary usage)
 */
export function createAlert(data: {
    device_id?: string;
    type: string;
    severity: string;
    title: string;
    explanation?: string;
    evidence?: string;
    confidence?: number;
}): AlertRecord {
    const db = getDb();

    /**
     * Normalize and construct alert object
     * 
     * Ensures:
     *  - Optional fields default to null 
     *  - Consistent structure across all alerts
     */
    const alert: AlertRecord = {
        id: randomUUID(),                       // Generate unique alert ID
        device_id: data.device_id || null,
        type: data.type,
        severity: data.severity,
        title: data.title,
        explanation: data.explanation || null,
        evidence: data.evidence || null,
        confidence: data.confidence ?? null,
        status: "active",                       // Default state
        created_at: Date.now()                  // Timestamp at creation
    };

    /**
     * Persist alert to database
     * 
     * Uses prepared statement for:
     *  - Performance
     *  - SQL injection safety
     */
    db.prepare(`
        INSERT INTO alerts (
            id, device_id, type, severity, title,
            explanation, evidence, confidence, status, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
        alert.id,
        alert.device_id,
        alert.type,
        alert.severity,
        alert.title,
        alert.explanation,
        alert.evidence,
        alert.confidence,
        alert.status,
        alert.created_at
    );

    // Return alert so caller (correlation engine) can use it immediately
    return alert;
}

/**
 * Returns all alerts ordered by newest first
 * 
 * Used by:
 *  - GET /alerts endpoint
 *  - Frontend dashboards
 * 
 * Behavior:
 *  - Sorted by created_at DESC for recent-first display
 */
export function listAlerts(): AlertRecord[] {
    const db = getDb();

    return db.prepare(`
        SELECT * FROM alerts
        ORDER BY created_at DESC
    `).all() as AlertRecord[];
}

/**
 * Fetch a single alert by ID
 * 
 * Used by:
 *  - GET /alerts/:id endpoint
 * 
 * Returns:
 *  - AlertRecord if found
 *  - undefined if no matching alert exists
 */
export function getAlert(id: string): AlertRecord | undefined {
    const db = getDb();

    return db.prepare(`
        SELECT * FROM alerts
        WHERE id = ?
    `).get(id) as AlertRecord | undefined;
}