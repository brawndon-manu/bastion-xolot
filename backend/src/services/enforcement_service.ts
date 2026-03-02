import { getDb } from "../db/db";
import { randomUUID } from "crypto";

/**
 * Records an enforcement action taken by the gateway
 * Not complete implementation
 */
export function createEnforcementAction(deviceId: string, action: string, reason: string) {
    const db = getDb();

    const record = {
        id: randomUUID(),
        device_id: deviceId,
        action,
        reason,
        initiated_by: "system",
        created_at: Date.now()
    };

    db.prepare(`
        INSERT INTO enforcement_actions
        VALUES (?, ?, ?, ?, ?, ?)
    `).run(
        record.id,
        record.device_id,
        record.action,
        record.reason,
        record.initiated_by,
        record.created_at
    );

    return record;
}