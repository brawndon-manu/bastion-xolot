import { getDb } from "../db/db";
import { config } from "../config";
import { getRealtimeStatus } from "../realtime/websocket";

export type ConsistencyIssue = {
    code: string;
    severity: "warning" | "error";
    message: string;
    count: number;
    sample?: Array<Record<string, unknown>>;
};

export type HealthSnapshot = {
    status: "ok" | "degraded";
    service: string;
    environment: string;
    monitor_only: boolean;
    auto_quarantine_threshold: number;
    alert_dedup_window_ms: number;
    anomaly_resolution_window_ms: number;
    resolved_anomaly_risk_decay: number;
    database: string;
    realtime: ReturnType<typeof getRealtimeStatus>;
    metrics: Record<string, number>;
    time: string;
};

export type ConsistencyReport = {
    status: "ok" | "warning" | "error";
    checked_at: string;
    issue_count: number;
    issues: ConsistencyIssue[];
};

/**
 * Builds the main health payload used by GET /health.
 * 
 * This keeps the route thin and makes it easier to reuse the same
 * operational snapshot from other diagnostics endpoints later.
 */
export function getHealthSnapshot(): HealthSnapshot {
    const db = getDb();
    const dbCheck = db.prepare("SELECT 1 as ok").get() as { ok: number };

    /**
     * These counts are intentionally small and cheap to compute.
     * They give a fast operational summary without needing a separate
     * dashboard query path.
     */
    const metrics = {
        devices_total: (db.prepare("SELECT COUNT(*) as count FROM devices").get() as { count: number }).count,
        quarantined_devices: (db.prepare("SELECT COUNT(*) as count FROM devices WHERE status = 'quarantined'").get() as { count: number }).count,
        active_alerts: (db.prepare("SELECT COUNT(*) as count FROM alerts WHERE status = 'active'").get() as { count: number }).count,
        resolved_alerts: (db.prepare("SELECT COUNT(*) as count FROM alerts WHERE status = 'resolved'").get() as { count: number }).count,
        open_anomalies: (db.prepare("SELECT COUNT(*) as count FROM anomalies WHERE status = 'open'").get() as { count: number }).count,
        resolved_anomalies: (db.prepare("SELECT COUNT(*) as count FROM anomalies WHERE status = 'resolved'").get() as { count: number }).count,
        enforcement_actions: (db.prepare("SELECT COUNT(*) as count FROM enforcement_actions").get() as { count: number }).count,
    };

    return {
        status: dbCheck.ok === 1 ? "ok" : "degraded",
        service: "bastion-backend",
        environment: config.NODE_ENV,
        monitor_only: config.MONITOR_ONLY,
        auto_quarantine_threshold: config.AUTO_QUARANTINE_THRESHOLD,
        alert_dedup_window_ms: config.ALERT_DEDUP_WINDOW_MS,
        anomaly_resolution_window_ms: config.ANOMALY_RESOLUTION_WINDOW_MS,
        resolved_anomaly_risk_decay: config.RESOLVED_ANOMALY_RISK_DECAY,
        database: dbCheck.ok === 1 ? "ok" : "degraded",
        realtime: getRealtimeStatus(),
        metrics,
        time: new Date().toISOString(),
    };
}

/**
 * Builds a lightweight consistency report for demo and operator checks.
 * 
 * The report looks for a few high-value issues:
 *  - duplicate device identities that may indicate fragmentation
 *  - active alerts that should probably have resolved already
 *  - open anomalies that have stayed open beyond the resolution window
 *  - records pointing at missing devices
 */
export function getConsistencyReport(): ConsistencyReport {
    const db = getDb();
    const issues: ConsistencyIssue[] = [];
    const now = Date.now();
    const staleAlertCutoff = now - config.ANOMALY_RESOLUTION_WINDOW_MS;

    /**
     * Duplicate MAC addresses are a strong signal that identity reconciliation
     * is fragmenting one physical device into multiple rows.
     */
    const duplicateMacs = db.prepare(`
        SELECT mac_address, COUNT(*) as count
        FROM devices
        WHERE mac_address IS NOT NULL
        GROUP BY mac_address
        HAVING COUNT(*) > 1
        ORDER BY count DESC, mac_address ASC
        LIMIT 5
    `).all() as Array<{ mac_address: string; count: number }>;

    if (duplicateMacs.length > 0) {
        issues.push({
            code: "duplicate_device_mac",
            severity: "warning",
            message: "Multiple device records share the same MAC address, which may indicate fragmented identity tracking.",
            count: duplicateMacs.reduce((sum, row) => sum + row.count, 0),
            sample: duplicateMacs.map((row) => ({ mac_address: row.mac_address, count: row.count })),
        });
    }

    /**
     * Duplicate IP addresses are noisier than duplicate MACs because DHCP can
     * reassign IPs, but they are still worth flagging for review.
     */
    const duplicateIps = db.prepare(`
        SELECT ip_address, COUNT(*) as count
        FROM devices
        WHERE ip_address IS NOT NULL
        GROUP BY ip_address
        HAVING COUNT(*) > 1
        ORDER BY count DESC, ip_address ASC
        LIMIT 5
    `).all() as Array<{ ip_address: string; count: number }>;

    if (duplicateIps.length > 0) {
        issues.push({
            code: "duplicate_device_ip",
            severity: "warning",
            message: "Multiple device records share the same IP address, which may indicate duplicate device entries or DHCP churn that needs review.",
            count: duplicateIps.reduce((sum, row) => sum + row.count, 0),
            sample: duplicateIps.map((row) => ({ ip_address: row.ip_address, count: row.count })),
        });
    }

    /**
     * Active alerts that have not been refreshed inside the anomaly resolution
     * window may indicate that lifecycle cleanup is not happening as expected.
     */
    const staleActiveAlerts = db.prepare(`
        SELECT id, type, device_id, updated_at
        FROM alerts
        WHERE status = 'active'
          AND updated_at <= ?
        ORDER BY updated_at ASC
        LIMIT 5
    `).all(staleAlertCutoff) as Array<{ id: string; type: string; device_id: string | null; updated_at: number }>;

    if (staleActiveAlerts.length > 0) {
        issues.push({
            code: "stale_active_alert",
            severity: "warning",
            message: "Some alerts are still active even though they have not been refreshed within the anomaly resolution window.",
            count: staleActiveAlerts.length,
            sample: staleActiveAlerts.map((row) => ({
                id: row.id,
                type: row.type,
                device_id: row.device_id,
                updated_at: row.updated_at,
            })),
        });
    }

    /**
     * Open anomalies older than the resolution window suggest the anomaly
     * lifecycle is stuck or the correlation path is not revisiting the device.
     */
    const staleOpenAnomalies = db.prepare(`
        SELECT id, device_id, updated_at
        FROM anomalies
        WHERE status = 'open'
          AND updated_at <= ?
        ORDER BY updated_at ASC
        LIMIT 5
    `).all(staleAlertCutoff) as Array<{ id: string; device_id: string; updated_at: number }>;

    if (staleOpenAnomalies.length > 0) {
        issues.push({
            code: "stale_open_anomaly",
            severity: "warning",
            message: "Some anomalies are still open even though they are older than the configured resolution window.",
            count: staleOpenAnomalies.length,
            sample: staleOpenAnomalies.map((row) => ({
                id: row.id,
                device_id: row.device_id,
                updated_at: row.updated_at,
            })),
        });
    }

    /**
     * These referential checks should normally stay empty because the backend
     * is designed to keep alerts and anomalies attached to known devices.
     * If they show up, the database state is inconsistent enough to treat as an error.
     */
    const alertsMissingDevices = db.prepare(`
        SELECT alerts.id, alerts.type, alerts.device_id
        FROM alerts
        LEFT JOIN devices ON devices.id = alerts.device_id
        WHERE alerts.device_id IS NOT NULL
          AND devices.id IS NULL
        LIMIT 5
    `).all() as Array<{ id: string; type: string; device_id: string }>;

    if (alertsMissingDevices.length > 0) {
        issues.push({
            code: "alert_missing_device",
            severity: "error",
            message: "Some alerts reference devices that no longer exist in the device table.",
            count: alertsMissingDevices.length,
            sample: alertsMissingDevices.map((row) => ({
                id: row.id,
                type: row.type,
                device_id: row.device_id,
            })),
        });
    }

    const anomaliesMissingDevices = db.prepare(`
        SELECT anomalies.id, anomalies.device_id
        FROM anomalies
        LEFT JOIN devices ON devices.id = anomalies.device_id
        WHERE devices.id IS NULL
        LIMIT 5
    `).all() as Array<{ id: string; device_id: string }>;

    if (anomaliesMissingDevices.length > 0) {
        issues.push({
            code: "anomaly_missing_device",
            severity: "error",
            message: "Some anomalies reference devices that no longer exist in the device table.",
            count: anomaliesMissingDevices.length,
            sample: anomaliesMissingDevices.map((row) => ({
                id: row.id,
                device_id: row.device_id,
            })),
        });
    }

    /**
     * Overall report status is intentionally simple:
     *  - error if any hard integrity issue exists
     *  - warning if only softer consistency issues exist
     *  - ok when nothing suspicious was found
     */
    const status = issues.some((issue) => issue.severity === "error")
        ? "error"
        : issues.length > 0
          ? "warning"
          : "ok";

    return {
        status,
        checked_at: new Date().toISOString(),
        issue_count: issues.length,
        issues,
    };
}
