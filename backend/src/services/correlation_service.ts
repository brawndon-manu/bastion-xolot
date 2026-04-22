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
import { explainSecurityEvent, generateAIExplanation } from "./plain_english";
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

type AlertSeverity = "low" | "medium" | "high";

const IDS_SEVERITY_PROFILE: Record<AlertSeverity, { riskDelta: number; confidence: number }> = {
    low: { riskDelta: 3, confidence: 0.45 },
    medium: { riskDelta: 8, confidence: 0.65 },
    high: { riskDelta: 18, confidence: 0.82 },
};

function normalizeAlertSeverity(value: unknown): AlertSeverity {
    const severity = typeof value === "string" ? value.toLowerCase() : "";
    if (severity === "high" || severity === "medium" || severity === "low") {
        return severity;
    }
    return "medium";
}

function isInformationalIdsSignal(event: Record<string, unknown>): boolean {
    const signature = String(event.signature || event.reason || "").toLowerCase();
    const category = String(event.category || "").toLowerCase();

    return (
        signature.startsWith("et info ") ||
        signature.includes("observed ") ||
        signature.includes("suricata stream") ||
        category.includes("not suspicious") ||
        category.includes("generic protocol command decode")
    );
}

function classifyIdsSeverity(event: Record<string, unknown>): AlertSeverity {
    const reportedSeverity = normalizeAlertSeverity(event.severity);

    if (isInformationalIdsSignal(event)) {
        return reportedSeverity === "high" ? "medium" : "low";
    }

    return reportedSeverity;
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
function createOrRefreshAlert(data: {
    device_id: string;
    type: string;
    severity: string;
    title: string;
    explanation: string;
    evidence: string;
    confidence: number;
    fingerprintParts: Array<string | number | null | undefined>;
}): AlertEmission {
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
            explanation: data.explanation,
            evidence: data.evidence,
            confidence: Math.max(existing.confidence ?? 0, data.confidence),
        });

        if (refreshed) {
            return { alert: refreshed, created: false };
        }
    }

    return {
        alert: createAlert({
            device_id: data.device_id,
            type: data.type,
            severity: data.severity,
            title: data.title,
            explanation: data.explanation,
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
function createBehavioralAlert(deviceId: string, anomaly: StoredAnomaly): AlertEmission {
    return createOrRefreshAlert({
        device_id: deviceId,
        type: anomaly.type,
        severity: anomaly.severity,
        title: "Behavioral anomaly detected",
        explanation: `${explainSecurityEvent("anomaly", anomaly)} ${anomaly.summary}.`,
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
function createCorrelatedThreatAlert(
    deviceId: string,
    event: Record<string, unknown>,
    anomalies: StoredAnomaly[],
    recentIdsSignals: StoredEvent[]
): AlertEmission {
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
        explanation: `${explainSecurityEvent("correlated_threat", event)} Recent anomaly count: ${anomalies.length}. Supporting IDS or suspicious connection count: ${recentIdsSignals.length}.`,
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
 * Fire-and-forget: asks Claude to rewrite a template explanation in plain English
 * and patches the stored alert when the response arrives.
 */
async function upgradeAlertExplanation(
    alertId: string,
    alertType: string,
    severity: string,
    title: string,
    evidence: string | null
): Promise<void> {
    let evidenceData: Record<string, unknown> = {};
    if (evidence) {
        try {
            evidenceData = JSON.parse(evidence);
        } catch {
            evidenceData = { raw: evidence };
        }
    }

    const aiExplanation = await generateAIExplanation(alertType, severity, title, evidenceData);
    if (!aiExplanation) return;

    const updated = refreshAlert(alertId, { explanation: aiExplanation });
    if (updated) {
        broadcast("alert.updated", updated);
    }
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
        alertEmissions.push(createOrRefreshAlert({
            device_id: deviceId,
            type: String(event.type),
            severity: "medium",
            title: `Blocked domain: ${event.domain || "unknown"}`,
            explanation: `Device attempted to access a blocked domain (${event.domain || "unknown"}). ${explainSecurityEvent("dns_block", event)}`,
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
        alertEmissions.push(createOrRefreshAlert({
            device_id: deviceId,
            type: String(event.type),
            severity: "high",
            title: "Suspicious outbound connection detected",
            explanation: "A device initiated an outbound connection that matched a suspicious destination pattern.",
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
        const idsSeverity = classifyIdsSeverity(event);
        const idsProfile = IDS_SEVERITY_PROFILE[idsSeverity];

        riskDelta = idsProfile.riskDelta;
        alertEmissions.push(createOrRefreshAlert({
            device_id: deviceId,
            type: String(event.type),
            severity: idsSeverity,
            title: `IDS Alert: ${event.signature || "Unknown threat"}`,
            explanation: explainSecurityEvent("ids_alert", event),
            evidence: JSON.stringify(event),
            confidence: idsProfile.confidence,
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
        alertEmissions.push(createBehavioralAlert(deviceId, ingestion.anomaly));
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
            createCorrelatedThreatAlert(deviceId, event, recentAnomalies, recentIdsSignals)
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
        try {
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
        } catch (err) {
            // DB action was recorded; edge sync failed — log and continue correlation
            console.error("Auto-quarantine edge sync failed for device", deviceId, err);
        }

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

        // For brand-new alerts, kick off an async AI explanation upgrade.
        // It resolves in the background and broadcasts alert.updated when done.
        if (emission.created) {
            upgradeAlertExplanation(
                emission.alert.id,
                emission.alert.type,
                emission.alert.severity,
                emission.alert.title,
                emission.alert.evidence,
            );
        }
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