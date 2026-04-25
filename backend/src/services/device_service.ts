import { randomUUID } from "crypto";
import { getDb, transaction } from "../db/db";

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
export type DeviceRole = "infrastructure" | "workstation" | "iot" | "unknown";

export type Device = {
    id: string;                     // Stable backend identifier for the device
    mac_address: string | null;     // MAC address, if known
    ip_address: string | null;      // Current IP address, if known
    hostname: string | null;        // Hostname from reverse lookup or event payload
    vendor: string | null;          // Manufacturer from OUI lookup
    first_seen: number;             // First time the device was observed
    last_seen: number;              // Most recent time the device was observed
    risk_score: number;             // Accumulated risk score used by correlation/enforcement
    status: string;                 // Current device state (e.g. normal, quarantined)
    role: DeviceRole;               // Operator-assigned device role (drives detection policy)
};

const VALID_ROLES = new Set<DeviceRole>(["infrastructure", "workstation", "iot", "unknown"]);

// IPs are not stable device identifiers — they change with DHCP and create ghost records
// that shadow proper MAC-based device records. Never use an IP string as a device ID.
const _IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

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
    vendor?: string;
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
        vendor: data.vendor ?? null,
        first_seen: Date.now(),
        last_seen: Date.now(),
        risk_score: 0,
        status: "normal",
        role: "unknown",
    };

    /**
     * Persist the new device.
     *
     * first_seen and last_seen are initialized to the same timestamp because
     * this is the first observation for the device.
     */
    db.prepare(`
        INSERT INTO devices (
            id, mac_address, ip_address, hostname, vendor,
            first_seen, last_seen, risk_score, status, role
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
        device.id,
        device.mac_address,
        device.ip_address,
        device.hostname,
        device.vendor,
        device.first_seen,
        device.last_seen,
        device.risk_score,
        device.status,
        device.role
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

function findDeviceByMac(mac: string): Device | undefined {
    const db = getDb();
    return db.prepare(`SELECT * FROM devices WHERE mac_address = ? ORDER BY last_seen DESC LIMIT 1`).get(mac) as Device | undefined;
}

function findDeviceByIp(ip: string): Device | undefined {
    const db = getDb();
    // Prefer a record that also has a MAC address (more authoritative identity)
    return db.prepare(`
        SELECT * FROM devices WHERE ip_address = ?
        ORDER BY CASE WHEN mac_address IS NOT NULL AND mac_address != '' THEN 0 ELSE 1 END, last_seen DESC
        LIMIT 1
    `).get(ip) as Device | undefined;
}

// Hostnames that are too generic to use as a unique device identifier.
const _GENERIC_HOSTNAMES = new Set([
    "localhost", "localhost.local", "unknown", "unknown.local",
]);

function isSpecificHostname(hostname: string): boolean {
    const lower = hostname.toLowerCase().trim();
    return lower.length > 0 && !_GENERIC_HOSTNAMES.has(lower);
}

function findDeviceByHostname(hostname: string): Device | undefined {
    if (!isSpecificHostname(hostname)) return undefined;
    const db = getDb();
    // Prefer the record most recently seen so we merge into the freshest identity
    return db.prepare(`
        SELECT * FROM devices WHERE LOWER(hostname) = LOWER(?)
        ORDER BY last_seen DESC
        LIMIT 1
    `).get(hostname) as Device | undefined;
}

/**
 * Promotes an IP-only device record to a proper MAC-based identity.
 *
 * Called when discovery sees a device with a full MAC address but an IP-only
 * record already exists for that IP (created earlier by an IDS alert or flow
 * event). Rather than leaving an unstable IP-keyed record in the DB, we:
 *  1. Create a new record with id = MAC (stable, hardware identity)
 *  2. Reassign all related rows (events, alerts, etc.) to the new ID
 *  3. Delete the old IP-only record
 *
 * All three steps run inside a single transaction so a failure leaves no
 * partial state.
 */
function promoteIpOnlyDevice(ipDevice: Device, data: DeviceInput): Device {
    const mac = data.mac_address!;
    const db = getDb();

    transaction(() => {
        db.prepare(`
            INSERT INTO devices (id, mac_address, ip_address, hostname, vendor, first_seen, last_seen, risk_score, status, role)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
            mac,
            mac,
            data.ip_address ?? ipDevice.ip_address,
            data.hostname ?? ipDevice.hostname,
            data.vendor ?? ipDevice.vendor,
            ipDevice.first_seen,
            Date.now(),
            ipDevice.risk_score,
            ipDevice.status,
            ipDevice.role ?? "unknown",
        );

        for (const table of ["events", "alerts", "anomalies", "metadata_summaries", "enforcement_actions"]) {
            db.prepare(`UPDATE ${table} SET device_id = ? WHERE device_id = ?`).run(mac, ipDevice.id);
        }

        const oldBl = db.prepare(`SELECT * FROM device_baselines WHERE device_id = ?`).get(ipDevice.id) as any;
        if (oldBl) {
            const newBl = db.prepare(`SELECT * FROM device_baselines WHERE device_id = ?`).get(mac) as any;
            if (!newBl) {
                db.prepare(`UPDATE device_baselines SET device_id = ? WHERE device_id = ?`).run(mac, ipDevice.id);
            } else {
                const total = oldBl.sample_count + newBl.sample_count;
                db.prepare(`
                    UPDATE device_baselines SET
                        avg_flow_count          = (avg_flow_count * sample_count + ? * ?) / ?,
                        avg_total_bytes         = (avg_total_bytes * sample_count + ? * ?) / ?,
                        avg_unique_destinations = (avg_unique_destinations * sample_count + ? * ?) / ?,
                        sample_count            = ?
                    WHERE device_id = ?
                `).run(
                    oldBl.avg_flow_count, oldBl.sample_count, total,
                    oldBl.avg_total_bytes, oldBl.sample_count, total,
                    oldBl.avg_unique_destinations, oldBl.sample_count, total,
                    total, mac,
                );
                db.prepare(`DELETE FROM device_baselines WHERE device_id = ?`).run(ipDevice.id);
            }
        }

        db.prepare(`DELETE FROM devices WHERE id = ?`).run(ipDevice.id);
    });

    return getDevice(mac)!;
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
 *  - otherwise keep the current database value
 */
function updateDeviceDetails(id: string, data: DeviceInput): void {
    const db = getDb();
    db.prepare(`
        UPDATE devices
        SET mac_address = COALESCE(?, mac_address),
            ip_address = COALESCE(?, ip_address),
            hostname = COALESCE(?, hostname),
            vendor = COALESCE(?, vendor),
            last_seen = ?
        WHERE id = ?
    `).run(
        data.mac_address ?? null,
        data.ip_address ?? null,
        data.hostname ?? null,
        data.vendor ?? null,
        Date.now(),
        id
    );
}

/**
 * Ensures a device record exists before other parts of the system reference it.
 *
 * Lookup priority (first match wins):
 *  1. Exact ID match
 *  2. MAC address match (same physical device, IP may have changed)
 *  3. IP address match, preferring records that already have a MAC
 *  4. Hostname match — catches MAC randomization where the same device
 *     reconnects with a rotated MAC but the same mDNS name
 *  5. Create a new record if nothing found
 *
 * Steps 2-4 prevent duplicate records when DHCP reassigns an IP, an event
 * arrives with only an IP identifier, or a device rotates its MAC address.
 */
export function ensureDeviceExists(data: DeviceInput): Device {
    const id = data.id || randomUUID();

    // Skip the byId shortcut when the id is an IP address — falling through to the
    // MAC/IP/hostname lookups finds the authoritative MAC-based record instead.
    if (!_IPV4_RE.test(id)) {
        const byId = getDevice(id);
        if (byId) {
            updateDeviceDetails(byId.id, data);
            return getDevice(byId.id)!;
        }
    }

    if (data.mac_address) {
        const byMac = findDeviceByMac(data.mac_address);
        if (byMac) {
            updateDeviceDetails(byMac.id, data);
            return getDevice(byMac.id)!;
        }
    }

    if (data.ip_address) {
        const byIp = findDeviceByIp(data.ip_address);
        if (byIp) {
            // If we have a MAC and the existing record is IP-only, promote it to
            // a stable MAC-based identity instead of leaving an IP-keyed record.
            if (data.mac_address && (!byIp.mac_address || byIp.mac_address === "")) {
                return promoteIpOnlyDevice(byIp, data);
            }
            updateDeviceDetails(byIp.id, data);
            return getDevice(byIp.id)!;
        }
    }

    if (data.hostname) {
        const byHostname = findDeviceByHostname(data.hostname);
        if (byHostname) {
            updateDeviceDetails(byHostname.id, data);
            return getDevice(byHostname.id)!;
        }
    }

    // Don't persist an IP string as the device ID — create with a UUID so we
    // don't accumulate ghost IP-keyed records alongside MAC-based records.
    return createDevice({ ...data, id: _IPV4_RE.test(id) ? randomUUID() : id });
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
        SET risk_score = MIN(MAX(risk_score + ?, 0), 100)
        WHERE id = ?
    `).run(delta, deviceId);

    return getDevice(deviceId);
}

export function updateDeviceRole(deviceId: string, role: string): Device | undefined {
    if (!VALID_ROLES.has(role as DeviceRole)) return undefined;
    const db = getDb();
    db.prepare(`UPDATE devices SET role = ? WHERE id = ?`).run(role, deviceId);
    return getDevice(deviceId);
}