import { AlertRecord, createAlert } from "./alert_service";
import { getDevice, updateDeviceRisk } from "./device_service";
import { quarantineDevice } from "./enforcement_service";
import { broadcast } from "../realtime/websocket";
import { explainSecurityEvent } from "./plain_english";
import {
    getRecentAnomalies,
    getRecentEventsByTypes,
    ingestEvent,
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
    event: StoredEvent;             // Persisted event record
    duplicate?: boolean;            // Boolean for duplicate
    alert?: AlertRecord;            // Most recent alert (for convenience)
    alerts: AlertRecord[];          // All alerts generated during processing
    anomaly?: StoredAnomaly;        // Behavioral anomaly (if detected)
    enforcement?: unknown;          // Enforcement action (quarantine, etc.)
    risk_score?: number;            // Updated device risk score
    device?: unknown;               // Updated device state
};

/**
 * Creates alert for behavioral anomalies
 * 
 * Used when anomaly detection system flags unsual behavior
 */
function createBehavioralAlert(deviceId: string, anomaly: StoredAnomaly): AlertRecord {
    return createAlert({
        device_id: deviceId,
        type: anomaly.type,
        severity: anomaly.severity,
        title: "Behavioral anomaly detected",
        explanation: `${explainSecurityEvent("anomaly", anomaly)} ${anomaly.summary}.`,
        evidence: anomaly.evidence,
        confidence: Math.min(0.99, anomaly.score / 50), // Normalize anomaly score -> confidence
    });
}

/**
 * Creates alert when multiple signals indicate a stronger threat
 * 
 * This is TRUE correlation (Phase 5):
 *  - Combines anomalies + events
 *  - Produces higher-condifence alert
 */
function createCorrelatedThreatAlert(
    deviceId: string,
    event: Record<string, unknown>,
    anomalies: StoredAnomaly[]
): AlertRecord {
    return createAlert({
        device_id: deviceId,
        type: "correlated_threat",
        severity: "high",
        title: "Correlated threat behavior detected",
        explanation: `${explainSecurityEvent("correlated_threat", event)} Recent anomaly count: ${anomalies.length}.`,
        evidence: JSON.stringify({ event, anomalies }),
        confidence: 0.96,
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

    let riskDelta = 0;                      // Risk score increment
    const alerts: AlertRecord[] = [];       // Alerts generated during processing
    let enforcement: unknown = null;        // Enforcement action (if triggered)

    /**
     * ==============================
     * RULE 1 - DNS BLOCK
     * ==============================
     */
    if (event.type === "dns_block") {
        riskDelta = 10;
        alerts.push(createAlert({
            device_id: deviceId,
            type: String(event.type),
            severity: "medium",
            title: `Blocked domain: ${event.domain || "unknown"}`,
            explanation: `Device attempted to access a blocked domain (${event.domain || "unknown"}). ${explainSecurityEvent("dns_block", event)}`,
            evidence: JSON.stringify(event),
            confidence: 0.8
        }));
    }

    /**
     * ==============================
     * RULE 2 - SUSPICIOUS CONNECTION
     * ==============================
     */
    if (event.type === "suspicious_connection") {
        riskDelta = 20;
        alerts.push(createAlert({
            device_id: deviceId,
            type: String(event.type),
            severity: "high",
            title: "Suspicious outbound connection detected",
            explanation: "A device initiated an outbound connection that matched a suspicious destination pattern.",
            evidence: JSON.stringify(event),
            confidence: 0.9
        }));
    }

    /**
     * ==============================
     * RULE 3 - IDS ALERT
     * ==============================
     */
    if (event.type === "ids_alert") {
        riskDelta = 25;
        alerts.push(createAlert({
            device_id: deviceId,
            type: String(event.type),
            severity: "high",
            title: `IDS Alert: ${event.signature || "Unknown threat"}`,
            explanation: explainSecurityEvent("ids_alert", event),
            evidence: JSON.stringify(event),
            confidence: 0.9
        }));
    }

    /**
     * ==============================
     * RULE 4 - BEHAVIORAL ANOMALY
     * ==============================
     */
    if (ingestion.anomaly) {
        riskDelta += ingestion.anomaly.score >= 40 ? 25 : 15;
        alerts.push(createBehavioralAlert(deviceId, ingestion.anomaly));
    }

    // No detection -> exist early
    if (riskDelta === 0) {
        return {
            event: ingestion.event,
            alerts,
            anomaly: ingestion.anomaly,
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
     * FETCH CONTEXT (for correlation)
     * ==============================
     */
    const recentAnomalies = getRecentAnomalies(deviceId, Date.now() - (60 * 60 * 1000));
    const recentIdsSignals = getRecentEventsByTypes(
        deviceId,
        ["ids_alert", "suspicious_connection"],
        Date.now() - (60 * 60 * 1000)
    );

    /**
     * ==============================
     * RULE 5 - CORRELATED THREAT
     * ==============================
     */
    if (
        device &&
        ((event.type === "dns_block" && device.risk_score > 20) ||
            (event.type === "ids_alert" && recentAnomalies.length > 0) ||
            (ingestion.anomaly && recentIdsSignals.length > 0))
    ) {
        alerts.push(createCorrelatedThreatAlert(deviceId, event, recentAnomalies));
    }

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
                    recentIdsSignals,
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
    for (const alert of alerts) {
        broadcast("alert.created", alert);
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
        enforcement,
        risk_score: device?.risk_score,
        device
    };
}