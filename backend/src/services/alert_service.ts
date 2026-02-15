/**
 * Creates an alert from a correlated security event.
 * Not complete implementation
 */
export async function createAlert(data: any) {
    return {
        id: "temp-alert-id",
        status: "open",
        ...data
    };
}

/**
 * Returns all alerts (placeholder).
 */
export async function getAlerts() {
    return [];
}