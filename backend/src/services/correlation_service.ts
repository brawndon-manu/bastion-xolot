import { createAlert } from "./alert_service";
import { updateDeviceRisk, getDevice } from "./device_service";
import { quarantineDevice } from "./enforcement_service";
import { broadcast } from "../realtime/websocket";


type CorrelationResult = {
    alert?: any;
    enforcement?: any;
    risk_score?: number;
    device?: any;
}

/**
 * Main intelligence engine of Bastion Xolot
 * 
 * Takes a raw event + device ID
 * Determines:
 *  - Is this suspicious?
 *  - Should we raise risk score?
 *  - Should we create an alert?
 *  - Should we enforce protection?
 */
export async function processEvent(event: any, deviceId: string): Promise<CorrelationResult> {
    let riskDelta = 0;
    let alert = null;
    let enforcement = null;

    /**
     * RULE 1 - Blocked DNS request
     */
    if (event.type === "dns_block") {
        riskDelta = 10;

        alert = await createAlert({
            device_id: deviceId,
            type: event.type,
            severity: "medium",
            title: `Blocked domain: ${event.domain || "unknown"}`,
            explanation: `Device attempted to access a known malicious domain (${event.domain || "unknown"}). This may indicate malware or phishing activity.`,
            evidence: JSON.stringify(event),
            confidence: 0.8
        });
    }

    /**
     * RULE 2 - Suspicious outbound connection
     */
    if (event.type === "suspicious_connection") {
        riskDelta = 20;

        alert = await createAlert({
            device_id: deviceId,
            type: event.type,
            severity: "high",
            title: "Suspicious outbound connection detected",
            explanation: "Connection to known malicious infrastructure",
            evidence: JSON.stringify(event),
            confidence: 0.9
        });
    }

    /**
     * RULE 3 - IDS Alert
     */
    if (event.type === "ids_alert") {
        riskDelta = 25;

        alert = await createAlert({
            device_id: deviceId,
            type: event.type,
            severity: "high",
            title: `IDS Alert: ${event.signature || "Unknown threat"}`,
            explanation: "Intrusion detection system flagged this traffic as malicious.",
            evidence: JSON.stringify(event),
            confidence: 0.9
        });
    }

    if (riskDelta === 0) {
        return {};
    }

    updateDeviceRisk(deviceId, riskDelta);
    const device = getDevice(deviceId);

    /**
     * RULE 4 - Correlated threat escalation
     */
    if (event.type === "dns_block" && device && device.risk_score > 20) {
        alert = await createAlert({
            device_id: deviceId,
            type: "correlated_threat",
            severity: "high",
            title: "Escalating threat behavior detected",
            explanation: "Device shows repeated malicious DNS activity and elevated risk score.",
            evidence: JSON.stringify(event),
            confidence: 0.95
        });
    }

    /**
     * RULE 5 - Automatic enforcement
     */
    if (device && device.risk_score >= 50 && device.status !== "quarantined") {
        enforcement = quarantineDevice(
            deviceId,
            "Risk score exceeded threshold"
        );
    }

    /**
     * REAL-TIME BROADCAST
     */
    if (alert) {
        broadcast("alert.created", alert);
    }

    if (enforcement) {
        broadcast("device.quarantined", enforcement);
    }

    return {
        alert,
        enforcement,
        risk_score: device?.risk_score,
        device
    };
}