/**
 * Converts techinal security data into human-readable explanation
 * Not complete implementation, AI later
 */
export function explainSecurityEvent(type: string, data: any): string {
    switch (type) {
        case "dns_block":
            return "A device on your network attempted to access a blocked or suspicious domain.";

        case "traffic_spike":
            return "A device generated unusually high network activity compared to its normal behavior.";
        
        case "anomaly":
            return "The system detected unusual network behavior from a device.";

        default:
            return "Suspicious network activity was detected.";
    }
}