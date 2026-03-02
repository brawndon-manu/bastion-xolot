import { createAlert } from "./alert_service";
import { updateDeviceRisk, getDevice } from "./device_service";
import { createEnforcementAction } from "./enforcement_service";

type CorrelationResult = {
    alert?: any;
    enforcement?: any;
    risk_score?: number;
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
            title: "Blocked malicious domain",
            explanation: "Device attempted to access a blocked domain",
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
     * If no rule matched -> nothing to do
     */
    if (riskDelta === 0) {
        return {};
    }

    /**
     * Update device risk score
     */
    updateDeviceRisk(deviceId, riskDelta);

    const device = getDevice(deviceId);

    /**
     * RULE 3 - Automatic enforcement threshold
     */
    if (device && device.risk_score >= 50) {
        enforcement = createEnforcementAction(
            deviceId,
            "isolate_device",
            "Risk score exceeded threshold"
        );
    }

    return {
        alert,
        enforcement,
        risk_score: device?.risk_score
    };
}