import { getDb } from "../db/db";
import { randomUUID } from "crypto";
import { broadcast } from "../realtime/websocket";
import { getDevice } from "./device_service";
import { config } from "../config";
import fs from "fs";
import path from "path";

/**
 * Represents a single enforcement action taken (or simulated) by the system.
 * 
 * This is the audit record for all response actions:
 *  - quarantine
 *  - unquarantine
 */
export type EnforcementAction = {
    id: string;                                     // Unique action ID
    device_id: string;                              // Target device
    action: "quarantine" | "unquarantine";          // Type of action
    reason: string;                                 // Why action was taken
    initiated_by: string;                           // system / operator
    created_at: number;                             // Timestamp
    mode: "active" | "monitor_only";                // Execution mode
    status: "applied" | "simulated" | "skipped";    // Result of action
    evidence: string | null;                        // Supporting content (JSON)
};

// Optional metadata passed when triggering enforcement
type EnforcementOptions = {
    initiated_by?: string;
    evidence?: string | null;
};

/**
 * Atomically writes the desired enforcement state for a device to the
 * shared desired_state.json file that the edge agent reconcile loop watches.
 *
 * state: "SOFT" = rate-limited, "HARD" = fully blocked, "NONE" = remove
 */
function syncDesiredState(
    mac: string,
    state: "SOFT" | "HARD" | "NONE",
    reason: string,
    actor: string,
): void {
    const filePath = config.DESIRED_STATE_PATH;
    const dir = path.dirname(filePath);

    try {
        fs.mkdirSync(dir, { recursive: true });

        let obj: Record<string, any> = { version: 1, devices: {} };
        if (fs.existsSync(filePath)) {
            try { obj = JSON.parse(fs.readFileSync(filePath, "utf8")); } catch { /* start fresh */ }
        }
        if (!obj.devices || typeof obj.devices !== "object") obj.devices = {};

        const now = new Date().toISOString();

        // Keep NONE entries with actor intact so the reconcile loop can route
        // operator-initiated deletes through the operator gate
        obj.devices[mac] = { state, reason, actor, updated_at: now };
        obj.updated_at = now;

        const tmp = filePath + ".tmp";
        fs.writeFileSync(tmp, JSON.stringify(obj), "utf8");
        fs.renameSync(tmp, filePath);
    } catch (err) {
        // Re-throw so callers know the edge agent was not updated.
        // An enforcement action recorded in the DB but not synced to the edge
        // means the device is NOT actually blocked — the caller must handle this.
        throw new Error(
            `Enforcement recorded but failed to sync to edge agent: ${err instanceof Error ? err.message : String(err)}`
        );
    }
}

/**
 * Persists enforcement action into database
 * 
 * Centralized helper ensures:
 *  - all actions are recorded consistently
 *  - audit trail is always maintained
 */
function recordAction(action: EnforcementAction): EnforcementAction {
    const db = getDb();
    db.prepare(`
        INSERT INTO enforcement_actions (
            id, device_id, action, reason, initiated_by, created_at, mode, status, evidence
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
        action.id,
        action.device_id,
        action.action,
        action.reason,
        action.initiated_by,
        action.created_at,
        action.mode,
        action.status,
        action.evidence
    );

    return action;
}

/**
 * Quarantines a device (or simulates it in monitor-only mode)
 *
 * Responsibilities:
 *  - Validate device exists
 *  - Determine execution mode (active vs monitor_only)
 *  - Prevent duplicate quarantine
 *  - Update device state if needed
 *  - Record action
 *  - Broadcast real-time update
 */
export function quarantineDevice(
    device_id: string,
    reason: string,
    options: EnforcementOptions = {}
): EnforcementAction {
    const db = getDb();
    const device = getDevice(device_id);

    // Ensure device exists before proceeding
    if (!device) {
        throw new Error(`Device ${device_id} not found`);
    }

    const initiatedBy = options.initiated_by || "system";

    // Monitor-only only suppresses automatic system actions
    const monitorOnly = config.MONITOR_ONLY && initiatedBy !== "operator";

    // Prevent duplicate enforcement
    const alreadyQuarantined = device.status === "quarantined";

    const status = alreadyQuarantined ? "skipped" : monitorOnly ? "simulated" : "applied";

    // Don't flood the log with repeated system-triggered simulated entries
    if (status === "simulated" && initiatedBy === "system") {
        const cutoff = Date.now() - 60 * 60 * 1000;
        const recent = db.prepare(`
            SELECT * FROM enforcement_actions
            WHERE device_id = ? AND action = 'quarantine' AND status = 'simulated' AND created_at >= ?
            LIMIT 1
        `).get(device_id, cutoff);
        if (recent) return recent as EnforcementAction;
    }

    const action: EnforcementAction = {
        id: randomUUID(),
        device_id,
        action: "quarantine",
        reason,
        initiated_by: initiatedBy,
        created_at: Date.now(),
        mode: config.MONITOR_ONLY ? "monitor_only" : "active",
        status,
        evidence: options.evidence ?? null,
    };

    if (!monitorOnly && !alreadyQuarantined) {
        // Use a conditional UPDATE as an atomic guard — if another concurrent call
        // already set status to 'quarantined', changes will be 0 and we skip enforcement.
        const result = db.prepare(`
            UPDATE devices
            SET status = 'quarantined'
            WHERE id = ? AND status != 'quarantined'
        `).run(device_id);

        if (result.changes === 0) {
            // Lost the race — another call quarantined this device first
            action.status = "skipped";
        }
    }

    recordAction(action);

    if (action.status === "applied") {
        syncDesiredState(device_id, "SOFT", reason, initiatedBy);
    }

    broadcast(
        action.status === "simulated" ? "device.monitor_only" : "device.quarantined",
        action
    );

    return action;
}

/**
 * Removes quarantine from a device
 *
 * Responsibilities:
 *  - Validate device exists
 *  - Check if device is actually quarantined
 *  - Respect monitor-only mode
 *  - Update device state if applicable
 *  - Record action
 *  - Broadcast update
 */
export function unquarantineDevice(
    device_id: string,
    options: EnforcementOptions = {}
): EnforcementAction {
    const db = getDb();
    const device = getDevice(device_id);

    if (!device) {
        throw new Error(`Device ${device_id} not found`);
    }

    const initiatedBy = options.initiated_by || "system";
    const monitorOnly = config.MONITOR_ONLY && initiatedBy !== "operator";
    const action: EnforcementAction = {
        id: randomUUID(),
        device_id,
        action: "unquarantine",
        reason: "manual_release",
        initiated_by: initiatedBy,
        created_at: Date.now(),
        mode: config.MONITOR_ONLY ? "monitor_only" : "active",
        status:
            device.status !== "quarantined"
                ? "skipped"
                : monitorOnly
                  ? "simulated"
                  : "applied",
        evidence: options.evidence ?? null,
    };

    if (!monitorOnly && device.status === "quarantined") {
        db.prepare(`
            UPDATE devices
            SET status = 'normal'
            WHERE id = ?
        `).run(device_id);
    }

    recordAction(action);

    if (action.status === "applied") {
        syncDesiredState(device_id, "NONE", "manual_release", initiatedBy);
    } else if (initiatedBy === "operator") {
        // Always sync on operator release — DB state may be stale but the nft set
        // could still have the device blocked. Force the reconcile loop to clear it.
        syncDesiredState(device_id, "NONE", "manual_release", initiatedBy);
    }

    broadcast(
        action.status === "simulated" ? "device.monitor_only" : "device.released",
        action
    );

    return action;
}

/**
 * Returns all enforcement actions (most recent first)
 * 
 * Used for:
 *  - GET /enforcement/history
 *  - auditing
 *  - UI display
 */
export function listEnforcementActions(): EnforcementAction[] {
    const db = getDb();

    return db.prepare(`
        SELECT * FROM enforcement_actions
        ORDER BY created_at DESC
    `).all() as EnforcementAction[];
}