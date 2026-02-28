import { randomUUID } from "crypto";
import { getDb } from "../db/db";

/**
 * Creates a new device record
 */
export function createDevice(data: {
    id?: string;
    mac_address?: string;
    ip_address?: string;
    hostname?: string;
}) {
    const db = getDb();

    const device = {
        id: data.id || randomUUID(),
        mac_address: data.mac_address || null,
        ip_address: data.ip_address || null,
        hostname: data.hostname || null,
        first_seen: Date.now(),
        last_seen: Date.now(),
        risk_score: 0,
        status: "normal"
    };

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
 * Returns device by ID
 */
export function getDevice(id: string) {
    const db = getDb();
    return db.prepare(`SELECT * FROM devices WHERE id = ?`).get(id);
}

/**
 * Updates last_seen timestamp when device appears again
 */
export function touchDevice(id: string) {
    const db = getDb();

    db.prepare(`
        UPDATE devices
        SET last_seen = ?
        WHERE id = ?
    `).run(Date.now(), id);
}

/**
 * Ensures a device exists.
 * If not -> creates it.
 * If yes -> update last_seen.
 */
export function ensureDeviceExists(data: {
    id?: string;
    mac_address?: string;
    ip_address?: string;
    hostname?: string;
}) {
    const id = data.id || randomUUID();

    const existing = getDevice(id);

    if (existing) {
        touchDevice(id);
        return existing;
    }

    return createDevice({ ...data, id});
}

/**
 * Returns all devices
 */
export function listDevices() {
    const db = getDb();
    return db.prepare(`SELECT * FROM devices`).all();
}