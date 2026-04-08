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

function normalizeMacAddress(value: string | undefined): string | undefined {
    return value?.trim().toLowerCase() || undefined;
}

function normalizeIpAddress(value: string | undefined): string | undefined {
    return value?.trim() || undefined;
}

function normalizeHostname(value: string | undefined): string | undefined {
    return value?.trim().toLowerCase() || undefined;
}

function normalizeDeviceInput(data: DeviceInput): DeviceInput {
    return {
        id: data.id?.trim() || undefined,
        mac_address: normalizeMacAddress(data.mac_address),
        ip_address: normalizeIpAddress(data.ip_address),
        hostname: normalizeHostname(data.hostname),
    };
}

function getDeviceByField(field: "mac_address" | "ip_address" | "hostname", value: string): Device | undefined {
    const db = getDb();
    return db.prepare(`SELECT * FROM devices WHERE ${field} = ? LIMIT 1`).get(value) as Device | undefined;
}

/**
 * Resolves the best existing device match from the available identifiers.
 * 
 * Matching priority is intentionally identity-first:
 *  - explicit backend id
 *  - MAC address
 *  - IP address
 *  - hostname
 * 
 * This helps prevent the same device from fragmenting across multiple rows
 * when later events carry a different identifier than the first sighting.
 */
function findMatchingDevice(data: DeviceInput): Device | undefined {
    if (data.id) {
        const byId = getDevice(data.id);
        if (byId) {
            return byId;
        }
    }

    if (data.mac_address) {
        const byMac = getDeviceByField("mac_address", data.mac_address);
        if (byMac) {
            return byMac;
        }
    }

    if (data.ip_address) {
        const byIp = getDeviceByField("ip_address", data.ip_address);
        if (byIp) {
            return byIp;
        }
    }

    if (data.hostname) {
        const byHostname = getDeviceByField("hostname", data.hostname);
        if (byHostname) {
            return byHostname;
        }
    }

    return undefined;
}

/**
 * Creates a brand-new device record and persists it.
 * 
 * Used when the backend sees a device for the first time.
 * If no ID is provided, the backend generates one.
 */
export function createDevice(data: DeviceInput): Device {
    const db = getDb();
    const normalized = normalizeDeviceInput(data);

    const device: Device = {
        id: normalized.id || randomUUID(),
        mac_address: normalized.mac_address ?? null,
        ip_address: normalized.ip_address ?? null,
        hostname: normalized.hostname ?? null,
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
    const normalized = normalizeDeviceInput(data);

    db.prepare(`
        UPDATE devices
        SET mac_address = COALESCE(?, mac_address),
            ip_address = COALESCE(?, ip_address),
            hostname = COALESCE(?, hostname),
            last_seen = ?
        WHERE id = ?
    `).run(
        normalized.mac_address ?? null,
        normalized.ip_address ?? null,
        normalized.hostname ?? null,
        Date.now(),
        id
    );
}

/**
 * Ensures a device record exists before other parts of the system reference it.
 * 
 * Behavior:
 *  - if device already exists -> refresh details and return updated record
 *  - if matching device exists under a different identifier -> reuse that device
 *  - if device does not exist -> create it and return new record
 * 
 * This is a key integrity function because alerts, events, and enforcement
 * actions should always point to a known device.
 */
export function ensureDeviceExists(data: DeviceInput): Device {
    const normalized = normalizeDeviceInput(data);
    const existing = findMatchingDevice(normalized);

    if (existing) {
        updateDeviceDetails(existing.id, normalized);
        return getDevice(existing.id)!;
    }

    return createDevice(normalized);
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
