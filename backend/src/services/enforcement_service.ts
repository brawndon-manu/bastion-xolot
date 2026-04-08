import { getDb } from "../db/db";
import { randomUUID } from "crypto";
import { broadcast } from "../realtime/websocket";
import { getDevice } from "./device_service";
import { config } from "../config";

/**
 * Represents a single enforcement action taken (or simulated) by the system.
 * 
 * This is the audit record for all response actions:
 *  - quarantine
 *  - unquarantine
 * 
 * Important for:
 *  - auditing
 *  - debugging
 *  - UI display
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

/**
 * Supported filters for enforcement history retrieval.
 */
export type EnforcementHistoryFilters = {
    device_id?: string;
    action?: string;
    status?: string;
    initiated_by?: string;
    limit?: number;
};

/**
 * Optional metadata passed when triggering enforcement
 */
type EnforcementOptions = {
    initiated_by?: string;
    evidence?: string | null;
};

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
 * Quaratines a device (or simulates it in monitor-only mode)
 * 
 * Responsibilites:
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

    const monitorOnly = config.MONITOR_ONLY;

    // Prevent duplicate enforcement
    const alreadyQuarantined = device.status === "quarantined";

    /**
     * Build enforcement action object
     */
    const action: EnforcementAction = {
        id: randomUUID(),
        device_id,
        action: "quarantine",
        reason,
        initiated_by: options.initiated_by || "system",
        created_at: Date.now(),
        mode: monitorOnly ? "monitor_only" : "active",

        /**
         * Determine execution result:
         *  - skipped -> already quarantined
         *  - simulated -> monitor-only made
         *  - Applied -> actual enforcement
         */
        status: alreadyQuarantined ? "skipped" : monitorOnly ? "simulated" : "applied",
        evidence: options.evidence ?? null,
    };

    /**
     * Apply enforcement ONLY if:
     *  - not in monitor-only mode
     *  - device is not already quarantined
     */
    if (!monitorOnly && !alreadyQuarantined) {
        db.prepare(`
            UPDATE devices
            SET status = 'quarantined'
            WHERE id = ?
        `).run(device_id);
    }

    // Record action in database
    recordAction(action);

    /**
     * Broadcast real-time update
     * 
     * Different event depending on mode:
     *  - simulated -> monitor_only
     *  - applied -> quarantined
     */
    broadcast(
        action.status === "simulated" ? "device.monitor_only" : "device.quarantined",
        action
    );

    return action;
}

/**
 * Removes quarantine from a device
 * 
 * Responsibilites:
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

    const monitorOnly = config.MONITOR_ONLY;
    const action: EnforcementAction = {
        id: randomUUID(),
        device_id,
        action: "unquarantine",
        reason: "manual_release",
        initiated_by: options.initiated_by || "system",
        created_at: Date.now(),
        mode: monitorOnly ? "monitor_only" : "active",

        /**
         * Determine outcome:
         *  - skipped -> device not quarantined
         *  - simulated -> monitor-only mode
         *  - applied -> actual release
         */
        status:
            device.status !== "quarantined"
                ? "skipped"
                : monitorOnly
                  ? "simulated"
                  : "applied",
        evidence: options.evidence ?? null,
    };

    /**
     * Apply release ONLY if:
     *  - not monitor-only
     *  - device is currently quarantined
     */
    if (!monitorOnly && device.status === "quarantined") {
        db.prepare(`
            UPDATE devices
            SET status = 'normal'
            WHERE id = ?
        `).run(device_id);
    }

    // Record action
    recordAction(action);

    /**
     * Broadcast real-time update
     */
    broadcast(
        action.status === "simulated" ? "device.monitor_only" : "device.released",
        action
    );

    return action;
}

/**
 * Returns enforcement actions ordered by newest first, with optional filters
 * for device, action type, outcome, operator, and result size.
 */
export function listEnforcementActions(filters: EnforcementHistoryFilters = {}): EnforcementAction[] {
    const db = getDb();
    const clauses: string[] = [];
    const params: Array<string | number> = [];

    if (filters.device_id) {
        clauses.push("device_id = ?");
        params.push(filters.device_id);
    }

    if (filters.action) {
        clauses.push("action = ?");
        params.push(filters.action);
    }

    if (filters.status) {
        clauses.push("status = ?");
        params.push(filters.status);
    }

    if (filters.initiated_by) {
        clauses.push("initiated_by = ?");
        params.push(filters.initiated_by);
    }

    const whereClause = clauses.length > 0
        ? `WHERE ${clauses.join(" AND ")}`
        : "";

    const limit = Math.max(1, Math.min(filters.limit ?? 100, 500));

    return db.prepare(`
        SELECT * FROM enforcement_actions
        ${whereClause}
        ORDER BY created_at DESC
        LIMIT ?
    `).all(...params, limit) as EnforcementAction[];
}
