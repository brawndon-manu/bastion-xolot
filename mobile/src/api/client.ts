import { Platform } from "react-native";

/**
 * API client for app
 * Handles REST requests
 * Websocket connection and event normalization
 */

type Listener = (event: any) => void;

let listeners: Listener[] = [];
let ws: WebSocket | null = null;
let memoryToken: string | null = null;

let _reconnectDelay = 1000;
let _reconnectTimer: ReturnType<typeof setTimeout> | null = null;
const MAX_RECONNECT_DELAY = 30000;
const FETCH_TIMEOUT_MS = 10000;

export type PairResult = { token: string };

/**
 * Frontend types used by the mobile UI
 */
export type DeviceRole = "infrastructure" | "workstation" | "iot" | "unknown";

export type Device = {
  id: string;
  name: string;
  ip: string;
  mac: string;
  hostname?: string;
  vendor: string | null;
  trusted: boolean;
  firstSeen: string;
  lastSeen: string;
  lastSeenMs: number;
  riskScore: number;
  status: string;
  role: DeviceRole;
};

export type Alert = {
  id: string;
  severity: "Low" | "Medium" | "High";
  deviceId: string;
  title: string;
  plainEnglish: string;
  evidence: string[];
  timestamp: string;
  timestampMs: number;
  type: string;
  confidence: number | null;
  sourceLabel: "Behavioral" | "IDS" | "Correlated" | "DNS" | "Suspicious Connection" | "General";
  status: string;
  updatedAt: string;
  resolvedAt: string | null;
  recommendedAction?: string;
};

/**
 * Enforcment action shape used by controls/history screens
 */
export type EnforcementAction = {
  id: string;
  deviceId: string;
  action: string;
  reason: string;
  initiatedBy: string;
  timestamp: string;
  mode: string;
  status: string;
  evidence: string | null;
};

export type HealthStatus = {
  status: string;
  service: string;
  environment: string;
  monitor_only: boolean;
  auto_quarantine_threshold: number;
  database: string;
  realtime: { initialized: boolean; client_count: number; };
  time: string;
};

/**
 * Raw backend device response types
 */
type BackendDevice = {
  id: string;
  mac_address: string | null;
  ip_address: string | null;
  hostname: string | null;
  first_seen: number;
  last_seen: number;
  risk_score: number;
  status: string;
  role: string;
};

type BackendAlert = {
  id: string;
  device_id: string | null;
  type: string;
  severity: string;
  title: string;
  explanation: string | null;
  evidence: string | null;
  confidence: number | null;
  status: string;
  created_at: number;
  updated_at: number;
  resolved_at: number | null;
};

type BackendEnforcementAction = {
  id: string;
  device_id: string;
  action: string;
  reason: string;
  initiated_by: string;
  created_at: number;
  mode?: string;
  status?: string;
  evidence?: string | null;
};


export const ONLINE_THRESHOLD_MS = 10 * 60 * 1000; // 10 minute threshold

/**
 * Robustly parses various timestamp formats into milliseconds.
 */
export function parseTimestamp(val: number | string | null | undefined): number {
  if (!val) return 0;

  // Handle number (seconds, ms, or micros)
  if (typeof val === "number") {
    if (val > 1_000_000_000_000_000) return val / 1000; // micros
    if (val > 1_000_000_000_000) return val; // ms
    if (val > 100_000_000) return val * 1000; // seconds
    return val;
  }

  // Handle string
  if (typeof val === "string") {
    // If it's a numeric string, parse it first
    if (/^\d+(\.\d+)?$/.test(val)) {
      return parseTimestamp(parseFloat(val));
    }
    // Otherwise try as Date string
    const d = new Date(val).getTime();
    if (!isNaN(d) && d > 0) return d;
  }

  return 0;
}

function toIso(ms: number) {
  if (!ms || ms <= 0) return new Date(0).toISOString();
  return new Date(ms).toISOString();
}

const API_PORT = 3000;

/**
 * IP of the Bastion Xolot appliance (Raspberry Pi) on the local network.
 */
const PI_HOST = "100.118.192.23";

function getHost()
{
  return PI_HOST;
}

/**
 * Base HTTP URL for REST calls
 */
function baseUrl() 
{
  return `http://${getHost()}:${API_PORT}`;
}

/**
 * Base Websocket URL for realtime updates
 */
function wsUrl() 
{
  return `ws://${getHost()}:${API_PORT}`;
}

/**
 * Maps backend device record into the frontend device shape
 */
function mapDevice(device: BackendDevice): Device 
{
  let ip = device.ip_address;
  let mac = device.mac_address;
  let hostname : string | undefined;

  if (device.hostname === null)
  {
   hostname = undefined;
  }
  else
  {
    hostname = device.hostname.replace(/\.local\.?$/i, "");
  }

  let name = "";
  
  if (!ip) 
  {
    ip = "—";
  }

  if (!mac)
  {
    mac = "—";
  }

  if (hostname)
  {
    name = hostname;
  } 
  else if (ip !== "—")
  {
    name = "Device " + ip;
  }
  else
  {
    name = "Device " + mac;
  }

  const lastSeenMs = parseTimestamp(device.last_seen);
  const firstSeenMs = parseTimestamp(device.first_seen);

  return {
    id: device.id,
    name: name,
    ip: ip,
    mac: mac,
    hostname: hostname,
    vendor: (device as any).vendor ?? null,
    trusted: true,
    firstSeen: toIso(firstSeenMs),
    lastSeen: toIso(lastSeenMs),
    lastSeenMs: lastSeenMs,
    riskScore: device.risk_score,
    status: device.status,
    role: (device.role as DeviceRole) ?? "unknown",
  };
}

/**
 * Normalizes backend severity strings for UI
 */
function mapSeverity(severity: string): "Low" | "Medium" | "High" 
{
  const lowerSeverity = severity.toLowerCase();
  
  if (lowerSeverity === "low")
  {
    return "Low";
  }

  if (lowerSeverity === "high") 
  {
    return "High";
  }

  return "Medium";
}

/**
 * Maps backend alert type values into cleaner sourcer labels for UI
 */
function mapSourceLabel(type: string): "Behavioral" | "IDS" | "Correlated" | "DNS" | "Suspicious Connection" | "General" 
{
  if (type === "behavioral_anomaly") 
  {
    return "Behavioral";
  }
  if (type === "ids_alert")
   { 
    return "IDS";
   }
  if (type === "correlated_threat") 
  {
    return "Correlated";
  }
  if (type === "dns_block")
  { 
    return "DNS";
  }
  if (type === "suspicious_connection")
  { 
    return "Suspicious Connection";
  }

  return "General";
}

/**
 * Converts backend evidence keys into human-readable display labels
 */
const evidenceLabelMap: { [key: string]: string } = {
  ip: "IP Address",
  ip_address: "IP Address",
  mac_address: "MAC Address",
  hostname: "Hostname",
  type: "Event Type",
  domain: "Domain",
  destination: "Destination",
  dest_ip: "Destination IP",
  timestamp: "Timestamp",
  signature: "IDS Signature",
  category: "Category",
  flow_count: "Flow Count",
  total_bytes: "Total Bytes",
  unique_destinations: "Unique Destinations",
  avg_flow_count: "Avg Flow Count",
  avg_total_bytes: "Avg Total Bytes",
  avg_unique_destinations: "Avg Unique Destinations",
  sample_count: "Sample Count",
  blocked_dns: "Blocked DNS",
  suspicious_connections: "Suspicious Connections",
  ids_alerts: "IDS Alerts",
  risk_score: "Risk Score",
  reason: "Reason",
  severity: "Severity",
  summary: "Summary",
  previousBaseline: "Previous Baseline",
  event: "Event",
  anomalies: "Anomalies",
  ids_context: "IDS Context",
  // Detection evidence fields
  evidence: "Detection Evidence",
  source_module: "Detection Module",
  // Anomaly detection fields
  anomaly_type: "Anomaly Type",
  current_connections: "Connections (Current)",
  current_bytes: "Bytes Sent (Current)",
  baseline_mean: "Baseline Average",
  baseline_stddev: "Baseline Std Dev",
  z_score: "Deviation Score",
  device_ip: "Device IP",
  new_destination_count: "New Destinations",
  known_destination_count: "Known Destinations",
  new_destinations: "New Destination IPs",
  sample_destinations: "Example New IPs",
  top_port_fanout_dest: "Scan Target IP",
  max_ports_single_dest: "Ports on Target",
  max_connections_single_dest: "Connections to Target",
  unique_ports: "Unique Ports",
  connections: "Total Connections",
  scan_candidates: "Scan Targets",
};

// Fields that are already surfaced elsewhere in the UI or are implementation details
const EVIDENCE_SKIP_KEYS = new Set([
  "id", "device_id", "source_event_id",
  "window_start", "window_end",
  "created_at", "updated_at", "resolved_at",
  // Edge alert wrapper fields already shown in dedicated UI sections
  "title", "explanation", "recommended_action",
  "related_event_ids", "recommended_enforcement",
  "confidence", "status", "metadata",
]);

function isEpochMs(v: unknown): v is number {
  return typeof v === "number" && v > 1_000_000_000_000;
}

function isUuid(v: unknown): boolean {
  return typeof v === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
}

function formatScalar(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  if (isUuid(v)) return null;
  if (isEpochMs(v)) return new Date(v).toLocaleString();
  if (typeof v === "number" && !Number.isInteger(v)) return v.toFixed(1);
  return String(v);
}

/**
 * Converts raw backend evidence into an array of readable strings.
 * Each entry gets its own ◆ bullet in the UI.
 */
function mapEvidence(evidence: string | null): string[]
{
  if (!evidence) { return []; }

  try {
    const parsed = JSON.parse(evidence);

    if (Array.isArray(parsed)) {
      return parsed.map(String);
    }

    if (parsed && typeof parsed === "object") {
      const result: string[] = [];

      for (const key in parsed) {
        if (EVIDENCE_SKIP_KEYS.has(key)) continue;

        const label = evidenceLabelMap[key] || key;
        const value = parsed[key];

        if (Array.isArray(value)) {
          result.push(label + ": " + value.length + " item(s)");
        } else if (typeof value === "object" && value !== null) {
          for (const innerKey in value as Record<string, unknown>) {
            if (EVIDENCE_SKIP_KEYS.has(innerKey)) continue;
            const innerLabel = evidenceLabelMap[innerKey] || innerKey;
            const innerValue = (value as any)[innerKey];
            if (Array.isArray(innerValue)) {
              result.push(label + " · " + innerLabel + ": " + innerValue.length + " item(s)");
            } else if (typeof innerValue === "object" && innerValue !== null) {
              // Flatten one more level (e.g. evidence.details.*), dropping the
              // intermediate key name for cleaner output
              for (const deepKey in innerValue as Record<string, unknown>) {
                if (EVIDENCE_SKIP_KEYS.has(deepKey)) continue;
                const deepLabel = evidenceLabelMap[deepKey] || deepKey;
                const formatted = formatScalar((innerValue as any)[deepKey]);
                if (formatted !== null) {
                  result.push(label + " · " + deepLabel + ": " + formatted);
                }
              }
            } else {
              const formatted = formatScalar(innerValue);
              if (formatted !== null) {
                result.push(label + " · " + innerLabel + ": " + formatted);
              }
            }
          }
        } else {
          const formatted = formatScalar(value);
          if (formatted !== null) {
            result.push(label + ": " + formatted);
          }
        }
      }

      return result;
    }

    return [String(parsed)];
  } 
  catch (error) 
  {
    return [evidence];
  }
}

/**
 * Maps backend alert into frontend alert shape
 */
function mapAlert(alert: BackendAlert): Alert
{
  let deviceId = alert.device_id;
  let explanation = alert.explanation;

  if (!deviceId)
  {
    deviceId = "";
  }

  if (!explanation)
  {
    explanation = "No explanation available.";
  }

  const createdMs = parseTimestamp(alert.created_at);

  // For edge alerts, extract the recommended_action the detection module wrote
  let recommendedAction: string | undefined;
  if (alert.type === "edge_alert" && alert.evidence) {
    try {
      const evidenceData = JSON.parse(alert.evidence);
      if (typeof evidenceData.recommended_action === "string" && evidenceData.recommended_action.trim()) {
        recommendedAction = evidenceData.recommended_action.trim();
      }
    } catch {
      // ignore parse errors
    }
  }

  return {
    id: alert.id,
    severity: mapSeverity(alert.severity),
    deviceId: deviceId,
    title: alert.title,
    plainEnglish: explanation,
    evidence: mapEvidence(alert.evidence),
    timestamp: toIso(createdMs),
    timestampMs: createdMs,
    type: alert.type,
    confidence: alert.confidence,
    sourceLabel: mapSourceLabel(alert.type),
    status: alert.status,
    updatedAt: toIso(parseTimestamp(alert.updated_at)),
    resolvedAt: alert.resolved_at ? toIso(parseTimestamp(alert.resolved_at)) : null,
    recommendedAction,
  };
}

/**
 * Maps backend enforcement action into frontend enforcement shape
 */
function mapEnforcementAction(action: BackendEnforcementAction): EnforcementAction 
{
  return {
    id: action.id,
    deviceId: action.device_id,
    action: action.action,
    reason: action.reason,
    initiatedBy: action.initiated_by,
    timestamp: toIso(action.created_at),
    mode: action.mode ?? "active",
    status: action.status ?? "applied",
    evidence: action.evidence ?? null
  };
}

/**
 * GET helper
 */
async function httpGet<T>(path: string): Promise<T>
{
  let url = baseUrl() + path;
  let headers: any =
  {
    "Content-Type": "application/json"
  };

  if (memoryToken)
  {
    headers["Authorization"] = "Bearer " + memoryToken;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30000); // 30s timeout

  try {
    let res = await fetch(url, {method: "GET", headers: headers, signal: controller.signal});

    if (!res.ok)
    {
      let text = "";
      try { text = await res.text(); } catch { text = ""; }
      throw new Error("HTTP " + res.status + " " + path + " " + text);
    }

    let data = await res.json();
    return data as T;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * POST helper
 */
async function httpPost<T>(path: string, body?: unknown): Promise<T>
{
  let url = baseUrl() + path;
  let headers: any =
  {
    "Content-Type": "application/json"
  };

  if (memoryToken)
  {
    headers["Authorization"] = "Bearer " + memoryToken;
  }

  let options: any =
  {
    method: "POST",
    headers: headers
  };

  if (body)
  {
    options.body = JSON.stringify(body);
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30000); // 30s timeout
  options.signal = controller.signal;

  try {
    let res = await fetch(url, options);

    if (!res.ok)
    {
      let text = "";
      try { text = await res.text(); } catch { text = ""; }
      throw new Error("HTTP " + res.status + " " + path + " " + text);
    }

    let data = await res.json();
    return data as T;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * PATCH helper
 */
async function httpPatch<T>(path: string, body?: unknown): Promise<T>
{
  let url = baseUrl() + path;
  let headers: any =
  {
    "Content-Type": "application/json"
  };

  if (memoryToken)
  {
    headers["Authorization"] = "Bearer " + memoryToken;
  }

  let options: any =
  {
    method: "PATCH",
    headers: headers
  };

  if (body)
  {
    options.body = JSON.stringify(body);
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30000);
  options.signal = controller.signal;

  try {
    let res = await fetch(url, options);

    if (!res.ok)
    {
      let text = "";
      try { text = await res.text(); } catch { text = ""; }
      throw new Error("HTTP " + res.status + " " + path + " " + text);
    }

    let data = await res.json();
    return data as T;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Main API object used by app
 * Handles health checks, alerts, devices, enforcement, realtime websocket updates
 */
export const api = {
  // still using local PIN update later
  pair: async (pin: string): Promise<PairResult> => {
    let trimmedPin = pin.trim();

    if (trimmedPin !== "1234") 
    {
      throw new Error("Invalid PIN (try 1234 for now)");
    }

    let token = "demo-token";
    memoryToken = token;
    
    return { token };
  },

  getStoredToken: async (): Promise<string | null> => {
    return memoryToken;
  },

  clearToken: async (): Promise<void> => {
    memoryToken = null;
  },

  health: async (): Promise<HealthStatus> => {
    let result = await httpGet<HealthStatus>("/health");
    return result;
  },

  setMonitorOnly: async (value: boolean): Promise<void> => {
    await httpPost("/config", { monitor_only: value });
  },

  /**
   * Fetches all known devices + alert by ID
   */
  getDevices: async (): Promise<Device[]> => {
    let rows = await httpGet<BackendDevice[]>("/devices");
    let devices: Device[] = [];
  
    for (let device of rows)
    {
      devices.push(mapDevice(device));
    }

    return devices;
  },

  getDevice: async (id: string): Promise<Device | null> => {
    let row = await httpGet<BackendDevice>("/devices/" + id);
    let device = mapDevice(row);
    return device;
  },

  updateDeviceRole: async (id: string, role: DeviceRole): Promise<Device> => {
    let row = await httpPatch<BackendDevice>("/devices/" + id, { role });
    return mapDevice(row);
  },

  /**
   * Fetches all alerts + alert by id
   */
  getAlerts: async (): Promise<Alert[]> => {
    let rows = await httpGet<BackendAlert[]>("/alerts");
    let alerts: Alert[] = [];

    for (let alert of rows)
    {
      alerts.push(mapAlert(alert));
    }

    return alerts;
  },

  getAlert: async (id: string): Promise<Alert | null> => {
    let row = await httpGet<BackendAlert>("/alerts/" + id);
    let alert = mapAlert(row);
    return alert;
  },

  resolveAlert: async (id: string): Promise<Alert> => {
    let row = await httpPost<BackendAlert>("/alerts/" + id + "/resolve");
    return mapAlert(row);
  },

  clearActiveAlerts: async (): Promise<{ cleared: number }> => {
    return httpPost<{ cleared: number }>("/alerts/clear-active");
  },

  /**
   * Requests manual quarantine of a device
   */
  quarantineDevice: async (id: string, reason = "manual_quarantine"): Promise<EnforcementAction> => {
    let row = await httpPost<BackendEnforcementAction>("/enforcement/quarantine/" + id, { reason: reason, initiated_by: "operator"});
    let action = mapEnforcementAction(row);
    return action;
  },

  /**
   * Requests release of a quarantined device
   */
  unquarantineDevice: async (id: string): Promise<EnforcementAction> => {
    let row = await httpPost<BackendEnforcementAction>("/enforcement/release/" + id, {initiated_by: "operator"});
    let action = mapEnforcementAction(row);
    return action;
  },

  /**
   * Fetches enforcement history
   */
  getEnforcementHistory: async (): Promise<EnforcementAction[]> => {
    let rows = await httpGet<BackendEnforcementAction[]>("/enforcement/history");
    let history: EnforcementAction[] = [];
    
    for (let action of rows)
    {
      history.push(mapEnforcementAction(action));
    }
    return history;
  },

/**
 * Opens Websocket connection
 */
  connectRealtime: () => {
    if (ws)
    {
      return;
    }

    ws = new WebSocket(wsUrl());

    ws.onopen = () => {
      _reconnectDelay = 1000; // reset backoff on successful connect
      listeners.forEach((listener) => listener({ type: "WS_OPEN" }));
    };

    ws.onclose = () => {
      listeners.forEach((listener) => listener({ type: "WS_CLOSED" }));
      ws = null;
      // reconnect with exponential backoff (1s → 2s → 4s … max 30s)
      _reconnectTimer = setTimeout(() => {
        _reconnectTimer = null;
        _reconnectDelay = Math.min(_reconnectDelay * 2, MAX_RECONNECT_DELAY);
        api.connectRealtime();
      }, _reconnectDelay);
    };

    ws.onerror = () => {
      listeners.forEach((listener) => listener({ type: "WS_ERROR" }));
    };

    ws.onmessage = (message) => {
      try {
        let parsedMessage = JSON.parse(String(message.data));

        if (!parsedMessage)
        {
          return;
        }

        if ((parsedMessage.event === "alert.created" || parsedMessage.event === "alert.updated") && parsedMessage.payload) 
        {
          let alert = mapAlert(parsedMessage.payload as BackendAlert);

          listeners.forEach((listener) => {
            listener({
              type: "ALERT_UPSERT",
              payload: alert
            });
          });

          return;
        }

      if (parsedMessage.event === "alert.resolved" && parsedMessage.payload) 
      {
        let alert = mapAlert(parsedMessage.payload as BackendAlert);

        listeners.forEach((listener) => {
          listener({
            type: "ALERT_RESOLVED",
            payload: alert
           });
          });

        return;
      }

      if ((parsedMessage.event === "device.quarantined" || parsedMessage.event === "device.released" || parsedMessage.event === "device.monitor_only") && parsedMessage.payload) 
      {
        let action = mapEnforcementAction(parsedMessage.payload as BackendEnforcementAction);

        listeners.forEach((listener) => {
          listener({
            type: "ENFORCEMENT_UPDATED",
            payload: action
          });
        });

        return;
      }

      if (parsedMessage.event === "device.seen" && parsedMessage.payload)
      {
        let device = mapDevice(parsedMessage.payload as BackendDevice);

        listeners.forEach((listener) => {
          listener({
            type: "DEVICE_SEEN",
            payload: device
          });
        });

        return;
      }

      listeners.forEach((listener) => {
        listener({
          type: "WS_EVENT",
          event: parsedMessage.event,
          payload: parsedMessage.payload
          });
          });
        } catch (error) {
          console.warn("WebSocket message parse error:", error);
        }
     };
  },

  /**
   * Closes the Websocket connection and cancels any pending reconnect
   */
  disconnectRealtime: () => {
    if (_reconnectTimer) {
      clearTimeout(_reconnectTimer);
      _reconnectTimer = null;
    }
    _reconnectDelay = 1000;
    if (ws) ws.close();
    ws = null;
  },

  /**
   *  Registers a realtime listener
   */
  subscribe: (listener: Listener) => {
    listeners.push(listener);

    return () => {
      listeners = listeners.filter((currentListener) => {
        return currentListener !== listener;
      });
   };
  }
};
