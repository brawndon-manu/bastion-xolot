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

import { getDb } from "../db/db";
import { randomUUID } from "crypto";

/**
 * Create and store a new alert
 * Called by correlation_service when suspicious behavior is detected
 */
export function createAlert(data: {
    device_id?: string;
    type: string;
    severity: string;
    title: string;
    explanation?: string;
    evidence?: string;
    confidence?: number;
}) {
    const db = getDb();

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

    return alert;
}

/**
 * Return all alerts ordered newest first
 * Used by GET /alerts
 */
export function listAlerts() {
    const db = getDb();

    return db.prepare(`
        SELECT * FROM alerts
        ORDER BY created_at DESC
    `).all();
}

/**
 * Fetch a single alert by ID
 * Used by GET /alerts/:id
 */
export function getAlert(id: string) {
    const db = getDb();

    return db.prepare(`
        SELECT * FROM alerts
        WHERE id = ?
    `).get(id);
}