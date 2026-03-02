import { Platform } from "react-native";

type Listener = (evt: any) => void;

let listeners: Listener[] = [];
let ws: WebSocket | null = null;

let memoryToken: string | null = null;

export type PairResult = { token: string };


export type Device = {
  id: string;
  name: string;
  ip: string;
  mac: string;
  hostname?: string;
  trusted: boolean;
  firstSeen: string;
  lastSeen: string;
};

export type Alert = {
  id: string;
  severity: "Low" | "Medium" | "High";
  deviceId: string;
  title: string;
  plainEnglish: string;
  evidence: string[];
  timestamp: string;
};

type BackendDevice = {
  id: string;
  mac_address: string | null;
  ip_address: string | null;
  hostname: string | null;
  first_seen: number;
  last_seen: number;
  risk_score: number;
  status: string;
};

function toIso(ms: number) {
  return new Date(ms).toISOString();
}

/**
* testing on android emulator - will remove later
*/
const API_PORT = 3000;

function baseUrl() {
  const host = Platform.OS === "android" ? "10.0.2.2" : "localhost";
  return `http://${host}:${API_PORT}`;
}

function wsUrl() {
  const host = Platform.OS === "android" ? "10.0.2.2" : "localhost";
  return `ws://${host}:${API_PORT}`;
}

function mapDevice(d: BackendDevice): Device {
  const ip = d.ip_address ?? "—";
  const mac = d.mac_address ?? "—";
  const hostname = d.hostname ?? undefined;

  const name = hostname ?? (ip !== "—" ? `Device ${ip}` : `Device ${mac}`);

  return {
    id: d.id,
    name,
    ip,
    mac,
    hostname,
    trusted: true,
    firstSeen: toIso(d.first_seen),
    lastSeen: toIso(d.last_seen)
  };
}

async function httpGet<T>(path: string): Promise<T> {
  const res = await fetch(`${baseUrl()}${path}`, {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
      ...(memoryToken ? { Authorization: `Bearer ${memoryToken}` } : {})
    }
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`HTTP ${res.status} ${path} ${text}`);
  }

  return (await res.json()) as T;
}

export const api = {
  // still using local PIN update later
  pair: async (pin: string): Promise<PairResult> => {
    if (pin.trim() !== "1234") throw new Error("Invalid PIN (try 1234 for now)");
    const token = "demo-token";
    memoryToken = token;
    return { token };
  },

  getStoredToken: async (): Promise<string | null> => {
    return memoryToken;
  },

  clearToken: async (): Promise<void> => {
    memoryToken = null;
  },

  health: async (): Promise<{ status: string }> => {
    return httpGet<{ status: string }>("/health");
  },

  /**
   *  devices from backend
   */
  getDevices: async (): Promise<Device[]> => {
    const rows = await httpGet<BackendDevice[]>("/devices");
    return rows.map(mapDevice);
  },

  getDevice: async (id: string): Promise<Device | null> => {
    const row = await httpGet<BackendDevice>(`/devices/${id}`);
    return mapDevice(row);
  },

  /**
   * update alerts in phase 2 TODO
   */
  getAlerts: async (): Promise<Alert[]> => {
    return [];
  },

  getAlert: async (id: string): Promise<Alert | null> => {
    return null;
  },

  quarantineDevice: async (id: string): Promise<{ success: boolean }> => {
    listeners.forEach((cb) =>
      cb({
        type: "ENFORCEMENT_UPDATED",
        payload: { deviceId: id, action: "QUARANTINE", timestamp: new Date().toISOString() }
      })
    );
    return { success: true };
  },

  unquarantineDevice: async (id: string): Promise<{ success: boolean }> => {
    listeners.forEach((cb) =>
      cb({
        type: "ENFORCEMENT_UPDATED",
        payload: { deviceId: id, action: "UNQUARANTINE", timestamp: new Date().toISOString() }
      })
    );
    return { success: true };
  },

  /**
   * phase 1 connects to backend WebSocket
   */
  connectRealtime: () => {
    if (ws) return;

    ws = new WebSocket(wsUrl());

    ws.onopen = () => {
      listeners.forEach((cb) => cb({ type: "WS_OPEN" }));
    };

    ws.onclose = () => {
      listeners.forEach((cb) => cb({ type: "WS_CLOSED" }));
      ws = null;
    };

    ws.onerror = () => {
      listeners.forEach((cb) => cb({ type: "WS_ERROR" }));
    };

    ws.onmessage = (msg) => {
      try {
        const parsed = JSON.parse(String(msg.data));
        listeners.forEach((cb) =>
          cb({
            type: "WS_EVENT",
            event: parsed.event,
            payload: parsed.payload
          })
        );
      } catch {
      }
    };
  },

  disconnectRealtime: () => {
    if (ws) ws.close();
    ws = null;
  },

  subscribe: (cb: Listener) => {
    listeners.push(cb);
    return () => {
      listeners = listeners.filter((x) => x !== cb);
    };
  }
};
