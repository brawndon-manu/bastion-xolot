import {
    AlertRecord,
    buildAlertFingerprint,
    createAlert,
    findRecentActiveAlert,
    refreshAlert,
    resolveAlertsForDevice,
} from "./alert_service";
import { getDevice, updateDeviceRisk } from "./device_service";
import { quarantineDevice } from "./enforcement_service";
import { broadcast } from "../realtime/websocket";
import { DeviceContext, explainSecurityEvent } from "./plain_english";
import { Device } from "./device_service";
import {
    getRecentAnomalies,
    getRecentEventsByTypes,
    ingestEvent,
    resolveStaleAnomalies,
    StoredAnomaly,
    StoredEvent,
} from "./event_service";
import { config } from "../config";

/**
 * Results returned by the correlation engine
 * 
 * Represents EVERYTHING that changed as a result of processing an event.
 * This allows:
 *  - API responses
 *  - WebSocket broadcasting
 *  - Frontend updates
 */
type CorrelationResult = {
    event: StoredEvent;                     // Persisted event record
    duplicate?: boolean;                    // Boolean for duplicate
    alert?: AlertRecord;                    // Most recent alert (for convenience)
    alerts: AlertRecord[];                  // Active alerts generated or refreshed during processing
    resolved_alerts?: AlertRecord[];        // Alerts resolved during lifecycle cleanup
    anomaly?: StoredAnomaly;                // Behavioral anomaly (if detected)
    resolved_anomalies?: StoredAnomaly[];   // Anomalies resolved during lifecycle cleanup
    enforcement?: unknown;                  // Enforcement action (quarantine, etc.)
    risk_score?: number;                    // Updated device risk score
    device?: any;                           // Updated device state
};

type AlertEmission = {
    alert: AlertRecord;
    created: boolean;
};

function toDeviceContext(
    device: Device | undefined,
    recentAnomalyCount?: number,
    recentIdsSignalCount?: number
): DeviceContext | undefined {
    if (!device) return undefined;
    return {
        hostname: device.hostname,
        vendor: device.vendor,
        ip_address: device.ip_address,
        risk_score: device.risk_score,
        status: device.status,
        first_seen: device.first_seen,
        recent_anomaly_count: recentAnomalyCount,
        recent_ids_signal_count: recentIdsSignalCount,
    };
}

function safeParseStoredEvent(event: StoredEvent): Record<string, unknown> {
    try {
        return JSON.parse(event.data) as Record<string, unknown>;
    } catch {
        return {
            id: event.id,
            type: event.type,
            timestamp: event.timestamp,
        };
    }
}

/**
 * Creates or refreshes an alert based on a stable fingerprint.
 * 
 * This reduces alert spam while still updating the latest evidence and confidence.
 */
async function createOrRefreshAlert(data: {
    device_id: string;
    type: string;
    severity: string;
    title: string;
    explanationFactory: () => Promise<string>;
    evidence: string;
    confidence: number;
    fingerprintParts: Array<string | number | null | undefined>;
}): Promise<AlertEmission> {
    const fingerprint = buildAlertFingerprint([
        data.device_id,
        data.type,
        ...data.fingerprintParts,
    ]);

    const existing = findRecentActiveAlert(
        data.device_id,
        fingerprint,
        Date.now() - config.ALERT_DEDUP_WINDOW_MS
    );

    if (existing) {
        const refreshed = refreshAlert(existing.id, {
            title: data.title,
            evidence: data.evidence,
            confidence: Math.max(existing.confidence ?? 0, data.confidence),
        });

        if (refreshed) {
            return { alert: refreshed, created: false };
        }
    }

    const explanation = await data.explanationFactory();

    return {
        alert: createAlert({
            device_id: data.device_id,
            type: data.type,
            severity: data.severity,
            title: data.title,
            explanation,
            evidence: data.evidence,
            confidence: data.confidence,
            fingerprint,
        }),
        created: true,
    };
}

/**
 * Creates alert for behavioral anomalies
 * 
 * Used when anomaly detection system flags unsual behavior
 */
async function createBehavioralAlert(
    deviceId: string,
    anomaly: StoredAnomaly,
    device?: Device
): Promise<AlertEmission> {
    return createOrRefreshAlert({
        device_id: deviceId,
        type: anomaly.type,
        severity: anomaly.severity,
        title: "Behavioral anomaly detected",
        explanationFactory: async () => `${await explainSecurityEvent("anomaly", anomaly, "standard", toDeviceContext(device))} ${anomaly.summary}.`,
        evidence: anomaly.evidence,
        confidence: Math.min(0.99, anomaly.score / 50),
        fingerprintParts: [anomaly.type],
    });
}

function calculateCorrelatedConfidence(
    event: Record<string, unknown>,
    anomalies: StoredAnomaly[],
    recentIdsSignals: StoredEvent[]
): number {
    let confidence = 0.78;

    if (event.type === "ids_alert") {
        confidence += 0.08;
    }

    confidence += Math.min(anomalies.length, 3) * 0.05;
    confidence += Math.min(recentIdsSignals.length, 3) * 0.03;

    return Math.min(0.98, confidence);
}

/**
 * Creates alert when multiple signals indicate a stronger threat
 * 
 * This is TRUE correlation (Phase 5):
 *  - Combines anomalies + events
 *  - Produces higher-confidence alert
 */
async function createCorrelatedThreatAlert(
    deviceId: string,
    event: Record<string, unknown>,
    anomalies: StoredAnomaly[],
    recentIdsSignals: StoredEvent[],
    device?: Device
): Promise<AlertEmission> {
    const confidence = calculateCorrelatedConfidence(event, anomalies, recentIdsSignals);
    const idsEvidence = recentIdsSignals.slice(0, 3).map((signal) => ({
        id: signal.id,
        type: signal.type,
        timestamp: signal.timestamp,
        data: safeParseStoredEvent(signal),
    }));

    return createOrRefreshAlert({
        device_id: deviceId,
        type: "correlated_threat",
        severity: "high",
        title: "Correlated threat behavior detected",
        explanationFactory: () => explainSecurityEvent(
            "correlated_threat",
            event,
            "standard",
            toDeviceContext(device, anomalies.length, recentIdsSignals.length)
        ),
        evidence: JSON.stringify({
            event,
            anomalies,
            ids_context: idsEvidence,
        }),
        confidence,
        fingerprintParts: [
            "correlated_threat",
            String(event.type),
            anomalies.map((anomaly) => anomaly.id).join(","),
            idsEvidence.map((signal) => signal.id).join(","),
        ],
    });
}

/**
 * ==================================
 * MAIN CORRELATION ENGINE
 * ==================================
 * 
 * This is the core intelligence layer of Bastion Xolot.
 * 
 * Responsibilities:
 *  - Ingest event
 *  - Detect suspicious behavior
 *  - Update device risk score
 *  - Generate alerts
 *  - Correlate multiple signals
 *  - Trigger enforcement
 *  - Broadcasts results in real-time
 */
export async function processEvent(event: Record<string, unknown>, deviceId: string): Promise<CorrelationResult> {
    /**
     * Persist event and run anomaly detection
     * 
     * ingestEvent:
     *  - Stores raw event
     *  - Runs anomaly detection
     *  - Returns structured result
     */
    const ingestion = ingestEvent(event, deviceId);

    if (ingestion.duplicate) {
        return {
            event: ingestion.event,
            duplicate: true,
            alerts: [],
        };
    }

    const sourceDevice = getDevice(deviceId);

    let riskDelta = 0;                          // Risk score increment
    const alertEmissions: AlertEmission[] = []; // Alerts generated during processing
    let enforcement: unknown = null;            // Enforcement action (if triggered)
    const now = Date.now();

    /**
     * ==============================
     * LIFECYCLE CLEANUP
     * ==============================
     * 
     * Resolve stale anomalies and their linked alerts after a quiet period.
     */
    let resolvedAnomalies: StoredAnomaly[] = [];
    let resolvedAlerts: AlertRecord[] = [];

    if (!ingestion.anomaly) {
        const resolutionCutoff = now - config.ANOMALY_RESOLUTION_WINDOW_MS;
        resolvedAnomalies = resolveStaleAnomalies(deviceId, resolutionCutoff);

        if (resolvedAnomalies.length > 0) {
            resolvedAlerts = resolveAlertsForDevice(
                deviceId,
                ["behavioral_anomaly", "correlated_threat"],
                resolutionCutoff
            );
        }
    }

    /**
     * ==============================
     * RULE 1 - DNS BLOCK
     * ==============================
     */
    if (event.type === "dns_block") {
        riskDelta = 10;
        alertEmissions.push(await createOrRefreshAlert({
            device_id: deviceId,
            type: String(event.type),
            severity: "medium",
            title: `Blocked domain: ${event.domain || "unknown"}`,
            explanationFactory: () => explainSecurityEvent("dns_block", event, "standard", toDeviceContext(sourceDevice)).then(e => `Device attempted to access a blocked domain (${event.domain || "unknown"}). ${e}`),
            evidence: JSON.stringify(event),
            confidence: 0.8,
            fingerprintParts: [event.type, String(event.domain || "unknown")],
        }));
    }

    /**
     * ==============================
     * RULE 2 - SUSPICIOUS CONNECTION
     * ==============================
     */
    if (event.type === "suspicious_connection") {
        riskDelta = 20;
        alertEmissions.push(await createOrRefreshAlert({
            device_id: deviceId,
            type: String(event.type),
            severity: "high",
            title: "Suspicious outbound connection detected",
            explanationFactory: async () => "A device initiated an outbound connection that matched a suspicious destination pattern.",
            evidence: JSON.stringify(event),
            confidence: 0.9,
            fingerprintParts: [
                event.type,
                String(event.destination || event.dest_ip || event.hostname || "unknown"),
            ],
        }));
    }

    /**
     * ==============================
     * RULE 3 - IDS ALERT
     * ==============================
     */
    if (event.type === "ids_alert") {
        riskDelta = 25;
        alertEmissions.push(await createOrRefreshAlert({
            device_id: deviceId,
            type: String(event.type),
            severity: "high",
            title: `IDS Alert: ${event.signature || "Unknown threat"}`,
            explanationFactory: () => explainSecurityEvent("ids_alert", event, "standard", toDeviceContext(sourceDevice)),
            evidence: JSON.stringify(event),
            confidence: 0.9,
            fingerprintParts: [
                event.type,
                String(event.signature || event.reason || "unknown"),
                String(event.category || "uncategorized"),
            ],
        }));
    }

    /**
     * ==============================
     * RULE 4 - BEHAVIORAL ANOMALY
     * ==============================
     */
    if (ingestion.anomaly) {
        riskDelta += ingestion.anomaly.score >= 40 ? 25 : 15;
        alertEmissions.push(await createBehavioralAlert(deviceId, ingestion.anomaly, sourceDevice));
    }

    /**
     * ==============================
     * FETCH CONTEXT (for correlation)
     * ==============================
     */
    const recentAnomalies = getRecentAnomalies(deviceId, now - (60 * 60 * 1000));
    const recentIdsSignals = getRecentEventsByTypes(
        deviceId,
        ["ids_alert", "suspicious_connection"],
        now - (60 * 60 * 1000)
    );

    /**
     * ==============================
     * RULE 5 - CORRELATED THREAT
     * ==============================
     */
    if (
        (event.type === "dns_block" && recentAnomalies.length > 0) ||
        (event.type === "ids_alert" && recentAnomalies.length > 0) ||
        (ingestion.anomaly && recentIdsSignals.length > 0)
    ) {
        alertEmissions.push(
            await createCorrelatedThreatAlert(deviceId, event, recentAnomalies, recentIdsSignals, sourceDevice)
        );
    }

    const alerts = alertEmissions.map((emission) => emission.alert);

    // No detection -> exit early after any lifecycle cleanup
    if (riskDelta === 0) {
        for (const resolvedAlert of resolvedAlerts) {
            broadcast("alert.resolved", resolvedAlert);
        }

        return {
            event: ingestion.event,
            alert: alerts[alerts.length - 1],
            alerts,
            anomaly: ingestion.anomaly,
            resolved_alerts: resolvedAlerts,
            resolved_anomalies: resolvedAnomalies,
        };
    }

    /**
     * ==============================
     * UPDATE DEVICE RISK
     * ==============================
     */
    let device = updateDeviceRisk(deviceId, riskDelta) || getDevice(deviceId);

    /**
     * ==============================
     * RULE 6 - AUTOMATIC ENFORCEMENT
     * ==============================
     */
    if (
        device &&
        device.risk_score >= config.AUTO_QUARANTINE_THRESHOLD &&
        device.status !== "quarantined"
    ) {
        enforcement = quarantineDevice(
            deviceId,
            "Risk score exceeded threshold",
            {
                initiated_by: "system",
                evidence: JSON.stringify({
                    event,
                    recentAnomalies,
                    recentIdsSignals: recentIdsSignals.map((signal) => ({
                        id: signal.id,
                        type: signal.type,
                        timestamp: signal.timestamp,
                    })),
                    risk_score: device.risk_score,
                }),
            }
        );

        // Refresh device state after enforcement
        device = getDevice(deviceId);
    }

    /**
     * ==============================
     * REAL-TIME BROADCAST
     * ==============================
     */
    for (const emission of alertEmissions) {
        broadcast(emission.created ? "alert.created" : "alert.updated", emission.alert);
    }

    for (const resolvedAlert of resolvedAlerts) {
        broadcast("alert.resolved", resolvedAlert);
    }

    /**
     * ==============================
     * RETURN RESULT
     * ==============================
     */
    return {
        event: ingestion.event,
        alert: alerts[alerts.length - 1],
        alerts,
        anomaly: ingestion.anomaly,
        resolved_alerts: resolvedAlerts,
        resolved_anomalies: resolvedAnomalies,
        enforcement,
        risk_score: device?.risk_score,
        device
    };
}
