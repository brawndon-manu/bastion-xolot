import { getDb } from "../db/db";
import { createHash, randomUUID } from "crypto";

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
    severity: string;               // Severity level (low, medium, high)
    title: string;                  // Short summary of the alert
    explanation: string | null;     // Human-readable explanation
    evidence: string | null;        // Raw evidence (JSON string)
    fingerprint: string | null;     // Stable deduplication key for repeated signals
    confidence: number | null;      // Confidence score (0-1)
    status: string;                 // Alert state (active, resolved, etc.)
    created_at: number;             // Timestamp (ms since epoch)
    updated_at: number;             // Most recent refresh time
    resolved_at: number | null;     // Resolution time for resolved alerts
};

/**
 * Builds a stable fingerprint for alert deduplication.
 * 
 * This allows repeated detections of the same condition to refresh one alert
 * instead of flooding the UI with duplicates.
 */
export function buildAlertFingerprint(parts: Array<string | number | null | undefined>): string {
    const normalized = parts
        .filter((value) => value !== undefined && value !== null && value !== "")
        .map((value) => String(value))
        .join("|");

    return createHash("sha1").update(normalized).digest("hex");
}

/**
 * Creates and persists a new alert
 * 
 * Responsibilites:
 *  - Normalize input data
 *  - Generate unique ID
 *  - Store alert in database
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
    fingerprint?: string;
    confidence?: number;
}): AlertRecord {
    const db = getDb();
    const now = Date.now();

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
        fingerprint: data.fingerprint || null,
        confidence: data.confidence ?? null,
        status: "active",                       // Default state
        created_at: now,                        // Timestamp at creation
        updated_at: now,
        resolved_at: null,
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
            explanation, evidence, fingerprint, confidence,
            status, created_at, updated_at, resolved_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
        alert.id,
        alert.device_id,
        alert.type,
        alert.severity,
        alert.title,
        alert.explanation,
        alert.evidence,
        alert.fingerprint,
        alert.confidence,
        alert.status,
        alert.created_at,
        alert.updated_at,
        alert.resolved_at
    );

    // Return alert so caller (correlation engine) can use it immediately
    return alert;
}

function getAlertById(id: string): AlertRecord | undefined {
    const db = getDb();
    return db.prepare(`
        SELECT * FROM alerts
        WHERE id = ?
    `).get(id) as AlertRecord | undefined;
}

/**
 * Looks up a recent active alert with the same fingerprint.
 * 
 * Used by correlation to refresh alerts instead of creating duplicates.
 */
export function findRecentActiveAlert(
    deviceId: string,
    fingerprint: string,
    since: number
): AlertRecord | undefined {
    const db = getDb();
    return db.prepare(`
        SELECT * FROM alerts
        WHERE device_id = ?
          AND fingerprint = ?
          AND status = 'active'
          AND updated_at >= ?
        ORDER BY updated_at DESC
        LIMIT 1
    `).get(deviceId, fingerprint, since) as AlertRecord | undefined;
}

/**
 * Refreshes an existing alert with newer evidence and timestamps.
 * 
 * This keeps the alert alive without creating duplicate rows.
 */
export function refreshAlert(id: string, patch: {
    title?: string;
    explanation?: string;
    evidence?: string;
    confidence?: number;
    status?: string;
    resolved_at?: number | null;
}): AlertRecord | undefined {
    const existing = getAlertById(id);
    if (!existing) {
        return undefined;
    }

    const updatedAt = Date.now();
    const status = patch.status ?? existing.status;
    const resolvedAt = status === "resolved"
        ? (patch.resolved_at ?? existing.resolved_at ?? updatedAt)
        : null;

    const nextAlert: AlertRecord = {
        ...existing,
        title: patch.title ?? existing.title,
        explanation: patch.explanation ?? existing.explanation,
        evidence: patch.evidence ?? existing.evidence,
        confidence: patch.confidence ?? existing.confidence,
        status,
        updated_at: updatedAt,
        resolved_at: resolvedAt,
    };

    const db = getDb();
    db.prepare(`
        UPDATE alerts
        SET title = ?,
            explanation = ?,
            evidence = ?,
            confidence = ?,
            status = ?,
            updated_at = ?,
            resolved_at = ?
        WHERE id = ?
    `).run(
        nextAlert.title,
        nextAlert.explanation,
        nextAlert.evidence,
        nextAlert.confidence,
        nextAlert.status,
        nextAlert.updated_at,
        nextAlert.resolved_at,
        nextAlert.id
    );

    return getAlertById(id);
}

/**
 * Marks matching active alerts as resolved when the underlying condition goes quiet.
 */
export function resolveAlertsForDevice(
    deviceId: string,
    types: string[],
    olderThan: number
): AlertRecord[] {
    if (types.length === 0) {
        return [];
    }

    const db = getDb();
    const placeholders = types.map(() => "?").join(", ");
    const now = Date.now();

    const alerts = db.prepare(`
        SELECT * FROM alerts
        WHERE device_id = ?
          AND type IN (${placeholders})
          AND status = 'active'
          AND updated_at <= ?
        ORDER BY updated_at DESC
    `).all(deviceId, ...types, olderThan) as AlertRecord[];

    if (alerts.length === 0) {
        return [];
    }

    const update = db.prepare(`
        UPDATE alerts
        SET status = 'resolved',
            updated_at = ?,
            resolved_at = ?
        WHERE id = ?
    `);

    for (const alert of alerts) {
        update.run(now, now, alert.id);
    }

    return alerts.map((alert) => ({
        ...alert,
        status: "resolved",
        updated_at: now,
        resolved_at: now,
    }));
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
    return getAlertById(id);
}
