import { getDb } from "../db/db";
import { randomUUID } from "crypto";
import { broadcast } from "../realtime/websocket";

/**
 * Quarantine a device
 */
export function quarantineDevice(device_id: string, reason: string) {
    const db = getDb();

    // Update device status
    db.prepare(`
        UPDATE devices
        SET status = 'quarantined'
        WHERE id = ?
    `).run(device_id);

    const action = {
        id: randomUUID(),
        device_id,
        action: "quarantine",
        reason,
        initiated_by: "system",
        created_at: Date.now()
    };

    // Record enforcement history
    db.prepare(`
        INSERT INTO enforcement_actions (
            id, device_id, action, reason, initiated_by, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
    `).run(
        action.id,
        action.device_id,
        action.action,
        action.reason,
        action.initiated_by,
        action.created_at
    );

    broadcast("device_quarantined", action);

    return action;
}

/**
 * Remove device quarantine
 */
export function unquarantineDevice(device_id: string) {
    const db = getDb();

    db.prepare(`
        UPDATE devices
        SET status = 'normal'
        WHERE id = ?
    `).run(device_id);

    const action = {
        id: randomUUID(),
        device_id,
        action: "unquarantine",
        reason: "manual_release",
        initiated_by: "system",
        created_at: Date.now()
    };

    db.prepare(`
        INSERT INTO enforcement_actions (
            id, device_id, action, reason, initiated_by, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
    `).run(
        action.id,
        action.device_id,
        action.action,
        action.reason,
        action.initiated_by,
        action.created_at
    );

    broadcast("device_released", action);

    return action;
}

/**
 * Get enforcement history
 */
export function listEnforcementActions() {
    const db = getDb();

    return db.prepare(`
        SELECT * FROM enforcement_actions
        ORDER BY created_at DESC
    `).all();
}
