import { randomUUID } from "crypto";
import { getDb } from "../db/db";

/**
 * Canonical device record used by the backend.
 * 
 * This represents the current known state of a device on the protected network.
 * It is used by:
 *  - event ingestion
 *  - correlation logic
 *  - enforcement decisions
 *  - device listing APIs
 */
export type Device = {
    id: string;                     // Stable backend identifier for the device
    mac_address: string | null;     // MAC address, if known
    ip_address: string | null;      // Current IP address, if known
    hostname: string | null;        // Hostname from reverse lookup or event payload
    first_seen: number;             // First time the device was observed
    last_seen: number;              // Most recent time the device was observed
    risk_score: number;             // Accumulated risk score used by correlation/enforcement
    status: string;                 // Current device state (e.g. normal, quarantined)
};

/**
 * Input shape used when creating or updating a device.
 * 
 * Device discovery and event ingestion may not always provide every field,
 * so there are optional
 */
type DeviceInput = {
    id?: string;
    mac_address?: string;
    ip_address?: string;
    hostname?: string;
};

/**
 * Creates a brand-new device record and persists it.
 * 
 * Used when the backend sees a device for the first time.
 * If no ID is provided, the backend generates one.
 */
export function createDevice(data: DeviceInput): Device {
    const db = getDb();

    const device: Device = {
        id: data.id || randomUUID(),
        mac_address: data.mac_address ?? null,
        ip_address: data.ip_address ?? null,
        hostname: data.hostname ?? null,
        first_seen: Date.now(),
        last_seen: Date.now(),
        risk_score: 0,
        status: "normal"
    };

    /**
     * Persist the new device.
     * 
     * first_seen and last_seen are initialized to the same timestamp because
     * this is the first observation for the device.
     */
    db.prepare(`
        INSERT INTO devices (
            id, mac_address, ip_address, hostname,
            first_seen, last_seen, risk_score, status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
        device.id,
        device.mac_address,
        device.ip_address,
        device.hostname,
        device.first_seen,
        device.last_seen,
        device.risk_score,
        device.status
    );

    return device;
}

/**
 * Fetches a single device by ID.
 * 
 * Returns:
 *  - Device if found
 *  - undefined if no matching records exists
 */
export function getDevice(id: string): Device | undefined {
    const db = getDb();
    return db.prepare(`SELECT * FROM devices WHERE id = ?`).get(id) as Device | undefined;
}

/**
 * Updates only the last_seen timestamp for a device.
 * 
 * Useful when a known device appears again and no other fields need to change.
 */
export function touchDevice(id: string): void {
    const db = getDb();

    db.prepare(`
        UPDATE devices
        SET last_seen = ?
        WHERE id = ?
    `).run(Date.now(), id);
}

/**
 * Updates device details without overwritting existing values with nulls.
 * 
 * COALESCE(?, existing_value) means:
 *  - use the new value if provided
 *  - otherwise keep th current database value
 * 
 * This is useful because event payloads may only contain partial device info.
 */
function updateDeviceDetails(id: string, data: DeviceInput): void {
    const db = getDb();
    db.prepare(`
        UPDATE devices
        SET mac_address = COALESCE(?, mac_address),
            ip_address = COALESCE(?, ip_address),
            hostname = COALESCE(?, hostname),
            last_seen = ?
        WHERE id = ?
    `).run(
        data.mac_address ?? null,
        data.ip_address ?? null,
        data.hostname ?? null,
        Date.now(),
        id
    );
}

/**
 * Ensures a device record exists before other parts of the system reference it.
 * 
 * Behavior:
 *  - if device already exists -> refresh details and return updated record
 *  - if device does not exist -> create it and return new record
 * 
 * This is a key integrity function because alerts, events, and enforcement
 * actions should always point to a known device.
 */
export function ensureDeviceExists(data: DeviceInput): Device {
    const id = data.id || randomUUID();

    const existing = getDevice(id);

    if (existing) {
        updateDeviceDetails(id, data);
        return getDevice(id)!;
    }

    return createDevice({ ...data, id });
}

/**
 * Returns all known devices ordered by most recently seen first.
 * 
 * Used by:
 *  - GET /devices
 *  - dashboards
 *  - device inventory views
 */
export function listDevices(): Device[] {
    const db = getDb();
    return db.prepare(`
        SELECT * FROM devices
        ORDER BY last_seen DESC
    `).all() as Device[];
}

/**
 * Updates the risk score of a device and returns the updated record.
 * 
 * MAX(risk_score + ?, 0) prevents the score from ever going negative.
 * 
 * This function is used by the correlation engine to:
 *  - increase risk when suspicious behavior is detected
 *  - potentially decrease risk later if you implement decay or recovery logic
 */
export function updateDeviceRisk(deviceId: string, delta: number): Device | undefined {
    const db = getDb();
    db.prepare(`
        UPDATE devices
        SET risk_score = MAX(risk_score + ?, 0)
        WHERE id = ?
    `).run(delta, deviceId);

    return getDevice(deviceId);
}