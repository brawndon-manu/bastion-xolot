/**
 * Alert Service
 * 
 * Responsible for:
 *  - Persisting alerts to database
 *  - Fetching alerts to database
 *  - Providing a clean interface for correlation logic
 * 
 * Not complete implementation
 */

import { db } from "../db/db";
import { randomUUID } from "crypto";

/**
 * Create and store a new alert
 * Called by correlation_service when suspicious behavior is detected
 */
export async function createAlert(data: {
    device_id?: string;
    type: string;
    severity: string;
    title: string;
    explanation?: string;
    evidence?: string;
    confidence?: number;
}) {
    const alert = {
        id: randomUUID(),
        device_id: data.device_id || null,
        type: data.type,
        severity: data.severity,
        title: data.title,
        explanation: data.explanation || null,
        evidence: data.evidence || null,
        confidence: data.confidence ?? null,
        status: "active",
        created_at: Date.now()
    };

    const stmt = db.prepare(`
        INSERT INTO alerts (
            id,
            device_id,
            type,
            severity,
            title,
            explanation,
            evidence,
            confidence,
            status,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
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

    return alert;
}

/**
 * Return all alerts ordered newest first
 * Used by GET /alerts
 */
export async function listAlerts() {
    const stmt = db.prepare(`
        SELECT * FROM alerts
        ORDER BY created_at DESC
    `);

    return stmt.all();
}

/**
 * Fetch a single alert by ID
 * Used by GET /alerts/:id
 */
export async function getAlert(id: string) {
    const stmt = db.prepare(`
        SELECT * FROM alerts
        WHERE id = ?
    `);

    return stmt.get(id);
}