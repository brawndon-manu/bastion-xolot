/**
 * Converts techinal security data into human-readable explanation
 * 
 * This function acts as the "translation layer" between:
 *  - raw detection logic (correlation engine)
 *  - user-facing explanations (mobile app / UI)
 * 
 * Used by:
 *  - correlation_service when creating alerts
 *  - enforcement logic (monitor-only explanations)
 */
export function explainSecurityEvent(type: string, data: any): string {
    switch (type) {

        /**
         * DNS block event
         * 
         * Triggered when a device attempts to resolve or acess
         * a domain that is known to be malicious or blocked.
         */
        case "dns_block":
            return "A device on your network attempted to access a blocked or suspicious domain.";

        /**
         * Traffic spike anomaly
         * 
         * Indicates abnormal network usage compared to baseline behavior
         */
        case "traffic_spike":
            return "A device generated unusually high network activity compared to its normal behavior.";
        
        /**
         * Generic anomaly detection
         * 
         * Used when behavior deviates from expected patterns,
         * but does not match a specific rule.
         */
        case "anomaly":
            return "The system detected unusual network behavior from a device.";

        /**
         * IDS alert
         * 
         * Uses optional signature field to provide more context.
         * Example:
         *  "ET MALWARE Command and Control"
         */
        case "ids_alert":
            return `The gateway IDS flagged this traffic as suspicious${data?.signature ? ` (${data.signature})` : ""}.`;

        /**
         * Correlated threat
         * 
         * Indicates multiple signals (events + anomalies) agree,
         * increasing confidence that this is a real threat
         */
        case "correlated_threat":
            return "Multiple signals agree that this device is behaving suspiciously, increasing confidence that the activity is real.";

        /**
         * Monitor-only enforcement
         * 
         * Device would normally be quarantined, but system is in
         * monitor-only mode (no actual enforcement applied)
         */
        case "enforcement.monitor_only":
            return "The device crossed the enforcement threshold, but the gateway is in monitor-only mode so no block was applied.";

        /**
         * Default fallback
         * 
         * Used when event type is unknown or not yet implemented
         */
        default:
            return "Suspicious network activity was detected.";
    }
}