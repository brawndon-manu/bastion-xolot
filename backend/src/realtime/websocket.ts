import { WebSocketServer, WebSocket } from "ws";
import { Server } from "http";

/**
 * Singleton WebSocket serer instance
 * 
 * - Initialized once during backend startup
 * - Shared across the entire application
 * - Used for broadcasting real-time security events
 */
let wss: WebSocketServer | null = null;

/**
 * Initialize WebSocket server
 * 
 * Attaches WebSocket server to the existing HTTP server. 
 */
export function initWebSocket(server: Server) {
    
    // Create WebSocket server bound to HTTP server
    wss = new WebSocketServer({ server });

    console.log("Realtime WebSocket ready");

    /**
     * Handle new client connections
     * 
     * Each connected client represents:
     *  - Mobile app instance
     *  - Dashboard UI
     *  - Monitoring client
     */
    wss.on("connection", (socket: WebSocket) => {
        console.log("Realtime client connected");

        /**
         * Handle client disconnect
         * 
         * Important for:
         *  - Monitoring active connections
         *  - Debugging connection stability
         */
        socket.on("close", () => {
            console.log("Realtime client disconnected");
        });
    });
}

/**
 * Broadcast event to all connected clients
 * 
 * Used for real-time updates such as:
 *  - alert.created
 *  - device.quarantined
 *  - device.risk.updated
 */
export function broadcast(event: string, payload: unknown) {
    
    // Safety check: ensure WebSocket is initialized
    if (!wss) {
        console.warn("WebSocket broadcast attempted before initialization");
        return;
    }

    /**
     * Standard message format
     * 
     * Example:
     * {
     *  event: "alert.created",
     *  payload: { ... }
     * }
     */
    const message = JSON.stringify({ event, payload });

    /**
     * Send message to all connected clients
     * 
     * Only sends to clients that are currently open
     * (prevents errors from closed connections)
     */
    for (const client of wss.clients) {
        if (client.readyState === WebSocket.OPEN) {
            try {
                client.send(message);
            } catch (err) {
                console.error("WebSocket send failed for client:", err);
            }
        }
    }
}

// Returns current WebSocket server status
export function getRealtimeStatus() {
    return {
        initialized: wss !== null,              // Whether WebSocket server is running
        client_count: wss?.clients.size ?? 0,   // Number of active connections
    };
}