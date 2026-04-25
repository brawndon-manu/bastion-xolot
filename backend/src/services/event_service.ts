import { randomUUID } from "crypto";
import { getDb } from "../db/db";

/**
 * Persisted raw event record.
 * This is the canonical stored form used by correlation lookups.
 */
export type StoredEvent = {
    id: string;
    device_id: string;
    type: string;
    timestamp: number;
    data: string;
};

/**
 * Derived metadata summary for a single ingested event.
 * These summaries are the building blocks for baselines and anomaly detection.
 */
export type MetadataSummary = {
    id: string;
    device_id: string;
    source_event_id: string;
    window_start: number;
    window_end: number;
    flow_count: number;
    total_bytes: number;
    unique_destinations: number;
    blocked_dns: number;
    suspicious_connections: number;
    ids_alerts: number;
    created_at: number;
};

// Simple rolling baseline for device behavior.
export type DeviceBaseline = {
    device_id: string;
    avg_flow_count: number;
    avg_total_bytes: number;
    avg_unique_destinations: number;
    sample_count: number;
    updated_at: number;
};

// Stored anomaly produced from baseline deviation.
export type StoredAnomaly = {
    id: string;
    device_id: string;
    source_event_id: string;
    type: string;
    severity: string;
    score: number;
    summary: string;
    evidence: string;
    status: string;
    created_at: number;
    updated_at: number;
    resolved_at: number | null;
};

/**
 * Result of ingesting a single event.
 * Duplicate events are short-circuited before summaries and anomalies are recalculated.
 */
export type EventIngestionResult = {
    event: StoredEvent;
    duplicate: boolean;
    summary?: MetadataSummary;
    baseline?: DeviceBaseline;
    anomaly?: StoredAnomaly;
};

// Accept epoch millis or parseable date strings; otherwise fall back to now.
function toTimestamp(value: unknown): number {
    if (typeof value === "number" && Number.isFinite(value)) {
        return value;
    }
    if (typeof value === "string") {
        const parsed = Date.parse(value);
        if (!Number.isNaN(parsed)) {
            return parsed;
        }
    }
    return Date.now();
}

// Normalizes numeric inputs used by flow summaries.
function toPositiveNumber(value: unknown, fallback = 0): number {
    if (typeof value === "number" && Number.isFinite(value) && value >= 0) {
        return value;
    }
    if (typeof value === "string") {
        const parsed = Number(value);
        if (Number.isFinite(parsed) && parsed >= 0) {
            return parsed;
        }
    }
    return fallback;
}

function getEventById(id: string): StoredEvent | undefined {
    const db = getDb();
    return db.prepare(`
        SELECT * FROM events
        WHERE id = ?
    `).get(id) as StoredEvent | undefined;
}

// Converts an arbitrary event payload into the normalized metrics we baseline against.
function deriveMetadataSummary(event: Record<string, unknown>, storedEvent: StoredEvent): MetadataSummary {
    const destination =
        event.destination ??
        event.dest_ip ??
        event.domain ??
        event.hostname;
    const flowCount =
        toPositiveNumber(event.flow_count, 0) ||
        (storedEvent.type === "flow_summary" || storedEvent.type === "suspicious_connection" ? 1 : 0);
    const totalBytes =
        toPositiveNumber(event.total_bytes, 0) ||
        toPositiveNumber(event.bytes, 0);
    const uniqueDestinations =
        toPositiveNumber(event.unique_destinations, 0) ||
        (destination ? 1 : 0);

    return {
        id: randomUUID(),
        device_id: storedEvent.device_id,
        source_event_id: storedEvent.id,
        window_start: storedEvent.timestamp,
        window_end: storedEvent.timestamp,
        flow_count: flowCount,
        total_bytes: totalBytes,
        unique_destinations: uniqueDestinations,
        blocked_dns: storedEvent.type === "dns_block" ? 1 : 0,
        suspicious_connections: storedEvent.type === "suspicious_connection" ? 1 : 0,
        ids_alerts: storedEvent.type === "ids_alert" ? 1 : 0,
        created_at: Date.now(),
    };
}

function insertMetadataSummary(summary: MetadataSummary): void {
    const db = getDb();
    db.prepare(`
        INSERT INTO metadata_summaries (
            id, device_id, source_event_id, window_start, window_end,
            flow_count, total_bytes, unique_destinations, blocked_dns,
            suspicious_connections, ids_alerts, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
        summary.id,
        summary.device_id,
        summary.source_event_id,
        summary.window_start,
        summary.window_end,
        summary.flow_count,
        summary.total_bytes,
        summary.unique_destinations,
        summary.blocked_dns,
        summary.suspicious_connections,
        summary.ids_alerts,
        summary.created_at
    );
}

// Inserts a new event, or returns the existing record if the event ID was replayed.
function insertEvent(rawEvent: Record<string, unknown>, deviceId: string): { event: StoredEvent; duplicate: boolean } {
    const db = getDb();
    const event: StoredEvent = {
        id: String(rawEvent.id ?? randomUUID()),
        device_id: deviceId,
        type: String(rawEvent.type ?? "unknown_event"),
        timestamp: toTimestamp(rawEvent.timestamp),
        data: JSON.stringify(rawEvent),
    };

    try {
        db.prepare(`
            INSERT INTO events (id, device_id, type, timestamp, data)
            VALUES (?, ?, ?, ?, ?)
        `).run(event.id, event.device_id, event.type, event.timestamp, event.data);

        return { event, duplicate: false };
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (!message.includes("UNIQUE constraint failed: events.id")) {
            throw error;
        }

        const existing = getEventById(event.id);
        if (!existing) {
            throw error;
        }

        return { event: existing, duplicate: true };
    }
}

function getBaseline(deviceId: string): DeviceBaseline | undefined {
    const db = getDb();
    return db.prepare(`
        SELECT * FROM device_baselines
        WHERE device_id = ?
    `).get(deviceId) as DeviceBaseline | undefined;
}

// Updates the device baseline with a rolling average.
function upsertBaseline(summary: MetadataSummary): DeviceBaseline {
    const db = getDb();
    const existing = getBaseline(summary.device_id);

    if (!existing) {
        const baseline: DeviceBaseline = {
            device_id: summary.device_id,
            avg_flow_count: summary.flow_count,
            avg_total_bytes: summary.total_bytes,
            avg_unique_destinations: summary.unique_destinations,
            sample_count: 1,
            updated_at: Date.now(),
        };

        db.prepare(`
            INSERT INTO device_baselines (
                device_id, avg_flow_count, avg_total_bytes,
                avg_unique_destinations, sample_count, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
        `).run(
            baseline.device_id,
            baseline.avg_flow_count,
            baseline.avg_total_bytes,
            baseline.avg_unique_destinations,
            baseline.sample_count,
            baseline.updated_at
        );

        return baseline;
    }

    const sampleCount = existing.sample_count + 1;
    const baseline: DeviceBaseline = {
        device_id: existing.device_id,
        avg_flow_count:
            ((existing.avg_flow_count * existing.sample_count) + summary.flow_count) / sampleCount,
        avg_total_bytes:
            ((existing.avg_total_bytes * existing.sample_count) + summary.total_bytes) / sampleCount,
        avg_unique_destinations:
            ((existing.avg_unique_destinations * existing.sample_count) + summary.unique_destinations) / sampleCount,
        sample_count: sampleCount,
        updated_at: Date.now(),
    };

    db.prepare(`
        UPDATE device_baselines
        SET avg_flow_count = ?,
            avg_total_bytes = ?,
            avg_unique_destinations = ?,
            sample_count = ?,
            updated_at = ?
        WHERE device_id = ?
    `).run(
        baseline.avg_flow_count,
        baseline.avg_total_bytes,
        baseline.avg_unique_destinations,
        baseline.sample_count,
        baseline.updated_at,
        baseline.device_id
    );

    return baseline;
}

/**
 * Flags obvious deviations from the rolling baseline.
 * This stays intentionally simple for demo reliability.
 */
function detectAnomaly(
    summary: MetadataSummary,
    previousBaseline: DeviceBaseline | undefined
): StoredAnomaly | undefined {
    if (!previousBaseline || previousBaseline.sample_count < 10) {
        return undefined;
    }

    let score = 0;
    const findings: string[] = [];

    if (summary.flow_count > Math.max(25, previousBaseline.avg_flow_count * 4)) {
        score += 20;
        findings.push("flow volume exceeded the established baseline");
    }

    if (summary.total_bytes > Math.max(250000, previousBaseline.avg_total_bytes * 3)) {
        score += 20;
        findings.push("traffic bytes spiked above the normal range");
    }

    if (summary.unique_destinations > Math.max(15, previousBaseline.avg_unique_destinations * 4)) {
        score += 15;
        findings.push("the device contacted an unusual number of destinations");
    }

    if (score < 20) {
        return undefined;
    }

    const severity = score >= 55 ? "high" : score >= 40 ? "medium" : "low";
    const now = Date.now();

    return {
        id: randomUUID(),
        device_id: summary.device_id,
        source_event_id: summary.source_event_id,
        type: "behavioral_anomaly",
        severity,
        score,
        summary: findings.join("; "),
        evidence: JSON.stringify({
            summary,
            previousBaseline,
        }),
        status: "open",
        created_at: now,
        updated_at: now,
        resolved_at: null,
    };
}

function insertAnomaly(anomaly: StoredAnomaly): void {
    const db = getDb();
    db.prepare(`
        INSERT INTO anomalies (
            id, device_id, source_event_id, type, severity,
            score, summary, evidence, status, created_at, updated_at, resolved_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
        anomaly.id,
        anomaly.device_id,
        anomaly.source_event_id,
        anomaly.type,
        anomaly.severity,
        anomaly.score,
        anomaly.summary,
        anomaly.evidence,
        anomaly.status,
        anomaly.created_at,
        anomaly.updated_at,
        anomaly.resolved_at
    );
}

/**
 * Main entrypoint for backend event ingestion.
 * New events are persisted, summarized, baselined, and optionally turned into anomalies.
 */
export function ingestEvent(rawEvent: Record<string, unknown>, deviceId: string): EventIngestionResult {
    const stored = insertEvent(rawEvent, deviceId);

    if (stored.duplicate) {
        return {
            event: stored.event,
            duplicate: true,
        };
    }

    const summary = deriveMetadataSummary(rawEvent, stored.event);
    const previousBaseline = getBaseline(deviceId);

    insertMetadataSummary(summary);
    const anomaly = detectAnomaly(summary, previousBaseline);
    if (anomaly) {
        insertAnomaly(anomaly);
    }

    const baseline = upsertBaseline(summary);
    return {
        event: stored.event,
        duplicate: false,
        summary,
        baseline,
        anomaly,
    };
}

export function getRecentAnomalies(deviceId: string, since: number): StoredAnomaly[] {
    const db = getDb();
    return db.prepare(`
        SELECT * FROM anomalies
        WHERE device_id = ?
          AND status = 'open'
          AND created_at >= ?
        ORDER BY created_at DESC
    `).all(deviceId, since) as StoredAnomaly[];
}

/**
 * Marks stale anomalies as resolved after a quiet period.
 * 
 * This gives the backend a basic lifecycle instead of leaving anomalies open forever.
 */
export function resolveStaleAnomalies(deviceId: string, olderThan: number): StoredAnomaly[] {
    const db = getDb();
    const now = Date.now();

    const anomalies = db.prepare(`
        SELECT * FROM anomalies
        WHERE device_id = ?
          AND status = 'open'
          AND updated_at <= ?
        ORDER BY updated_at DESC
    `).all(deviceId, olderThan) as StoredAnomaly[];

    if (anomalies.length === 0) {
        return [];
    }

    const update = db.prepare(`
        UPDATE anomalies
        SET status = 'resolved',
            updated_at = ?,
            resolved_at = ?
        WHERE id = ?
    `);

    for (const anomaly of anomalies) {
        update.run(now, now, anomaly.id);
    }

    return anomalies.map((anomaly) => ({
        ...anomaly,
        status: "resolved",
        updated_at: now,
        resolved_at: now,
    }));
}

// Used by correlation to look back for IDS or connection context around a device.
export function getRecentEventsByTypes(
    deviceId: string,
    types: string[],
    since: number
): StoredEvent[] {
    if (types.length === 0) {
        return [];
    }

    const db = getDb();
    const placeholders = types.map(() => "?").join(", ");
    return db.prepare(`
        SELECT * FROM events
        WHERE device_id = ?
          AND type IN (${placeholders})
          AND timestamp >= ?
        ORDER BY timestamp DESC
    `).all(deviceId, ...types, since) as StoredEvent[];
}
