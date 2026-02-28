import { randomUUID } from "crypto";
import { getDb } from "../db/db";

/**
 * Canonical device model used across backend.
 * This defines the contract for what a device is.
 */
export type Device = {
    id: string;
    mac_address: string | null;
    ip_address: string | null;
    hostname: string | null;
    first_seen: number;
    last_seen: number;
    risk_score: number;
    status: string;
};

/**
 * Creates a new device record in the database
 */
export function createDevice(data: {
    id?: string;
    mac_address?: string;
    ip_address?: string;
    hostname?: string;
}): Device {
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
export function getDevice(id: string): Device | undefined {
    const db = getDb();
    return db.prepare(`SELECT * FROM devices WHERE id = ?`).get(id) as Device | undefined;
}

/**
 * Updates last_seen timestamp when device appears again
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
 * Ensures a device exists.
 * If not -> creates it.
 * If yes -> updates last_seen.
 * ALWAYS returns a valid Device object.
 */
export function ensureDeviceExists(data: {
    id?: string;
    mac_address?: string;
    ip_address?: string;
    hostname?: string;
}): Device {
    const id = data.id || randomUUID();

    const existing = getDevice(id);

    if (existing) {
        touchDevice(id);
        return existing;
    }

    return createDevice({ ...data, id });
}

/**
 * Returns all devices
 */
export function listDevices(): Device[] {
    const db = getDb();
    return db.prepare(`SELECT * FROM devices`).all() as Device[];
}