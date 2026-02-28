import { WebSocketServer, WebSocket } from "ws";
import { Server } from "http";

/**
 * Singleton WebSocket server instance
 * Null until initialized during backend startup
 */
let wss: WebSocketServer | null = null;

/**
 * Initialize Websocket server
 * Shares the same HTTP server used by Express
 */
export function initWebSocket(server: Server) {
    wss = new WebSocketServer({ server });

    console.log("Realtime WebSocket ready");

    wss.on("connection", (socket: WebSocket) => {
        console.log("Realtime client connected");

        socket.on("close", () => {
            console.log("Realtime client disconnected");
        });
    });
}

/**
 * Broadcast structured event to all connected clients
 * Used by:
 *  - alert_service
 *  - device_service (future)
 *  - enforcement_service (future)
 */
export function broadcast(event: string, payload: unknown) {
    if (!wss) {
        console.warn("WebSocket broadcast attempted before initialization");
        return;
    }

    const message = JSON.stringify({ event, payload });

    for (const client of wss.clients) {
        if (client.readyState === WebSocket.OPEN) {
            client.send(message);
        }
    }
}