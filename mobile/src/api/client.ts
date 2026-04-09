import { Platform } from "react-native";
/**
* API client for app
*/

type Listener = (event: any) => void;

let listeners: Listener[] = [];
let ws: WebSocket | null = null;
let memoryToken: string | null = null;

export type PairResult = { token: string };

/*
* frontend types used by mobile screens / components
*/

export type Device = {
  id: string;
  name: string;
  ip: string;
  mac: string;
  hostname?: string;
  trusted: boolean;
  firstSeen: string;
  lastSeen: string;
  riskScore: number;
  status: string;
};

export type Alert = {
  id: string;
  severity: "Low" | "Medium" | "High";
  deviceId: string;
  title: string;
  plainEnglish: string;
  evidence: string[];
  timestamp: string;
  type: string;
  confidence: number | null;
  sourceLabel: "Behavioral" | "IDS" | "Correlated" | "DNS" | "Connection" | "General";
  status: string;
  updatedAt: string;
  resolvedAt: string | null;
};

/**
* PHASE 4: enforcement actions for quarantine / release 
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

/*
* backend response types
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


function toIso(millisecs: number) 
{
  return new Date(millisecs).toISOString();
}

const API_PORT = 3000;
const IOS_DEV_HOST = "192.168.1.50"; // CHANGE LATER

/** 
* android for windows testing
* ios final 
*/

function getHost() 
{
  if (Platform.OS === "android") 
  {
    return "10.0.2.2";
  }

  return IOS_DEV_HOST;
}

function baseUrl() 
{
  return `http://${getHost()}:${API_PORT}`;
}

function wsUrl() 
{
  return `ws://${getHost()}:${API_PORT}`;
}

/**
* 
* PHASE 1: device inventory
* PHASE 3: riskscore, devicestatus
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
    hostname = device.hostname;
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

  return {
    id: device.id,
    name: name,
    ip: ip,
    mac: mac,
    hostname: hostname,
    trusted: true,
    firstSeen: toIso(device.first_seen),
    lastSeen: toIso(device.last_seen),
    riskScore: device.risk_score,
    status: device.status
  };
}

/**
* convverts backend severity strings
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

function mapSourceLabel(type: string): "Behavioral" | "IDS" | "Correlated" | "DNS" | "Connection" | "General" 
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
    return "Connection";
  }

  return "General";
}
/*
* convert backend eveidence into string array for displaying
*/

function mapEvidence(evidence: string | null): string[] 
{
  
  if (!evidence)
  {
    return [];
  }

  try {
    let parsed = JSON.parse(evidence);

    if (Array.isArray(parsed)) 
    {
      let result: string[] = [];
      
      for(const item of parsed)
      {
        result.push(String(item));
      }

      return result;
    }

    if (typeof parsed === "object")
    {
      let result: string[] = [];

      for (let key in parsed)
      {
        let label = key;

      if (key === "device_id") 
      {
        label = "Device ID";
      }
      else if (key === "ip") 
      {
        label = "IP Address";
      }
      else if (key === "hostname") 
      {
        label = "Hostname";
      }
      else if (key === "type") 
      {
        label = "Event Type";
      }

        result.push(label + ": " + String(parsed[key]));
      }
      
      return result;
    }

    return [String(parsed)];

  } catch (error) {
    return [evidence];
  }
}

/*
* covert backend alert into frontend alert
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

  return {
    id: alert.id,
    severity: mapSeverity(alert.severity),
    deviceId: deviceId,
    title: alert.title,
    plainEnglish: explanation,
    evidence: mapEvidence(alert.evidence),
    timestamp: toIso(alert.created_at),
    type: alert.type,
    confidence: alert.confidence,
    sourceLabel: mapSourceLabel(alert.type),
    status: alert.status,
    updatedAt: toIso(alert.updated_at),
    resolvedAt: alert.resolved_at ? toIso(alert.resolved_at) : null
  };
}

/*
* convert backend enforcement action into frontend format
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

/*
* GET helper
* send GET requests, attach JSON headers & auth token
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

  let res = await fetch(url, {method: "GET", headers: headers});

  if (!res.ok)
  {
    let text = "";

    try {
      text = await res.text();
    } 
    catch (error) {
      text = "";
    }

    throw new Error("HTTP " + res.status + " " + path + " " + text);
  }

  let data = await res.json();
  return data as T;
}

/*
* POST helper
* send POST requests, etc
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

  let res = await fetch(url, options);
    
  if (!res.ok) 
  {
    let text = "";
    
    try {
      text = await res.text();
    } 
    catch (error) {
      text = "";
    }

    throw new Error("HTTP " + res.status + " " + path + " " + text);
  }

  let data = await res.json();
  return data as T;
}

/*
* main API object used by app
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

  /**
   *  devices from backend
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

/*
* alerts from backend
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

/*
* enforcement controls
* manual quarantine / release + history
*/
  quarantineDevice: async (id: string, reason = "manual_quarantine"): Promise<EnforcementAction> => {
    let row = await httpPost<BackendEnforcementAction>("/enforcement/quarantine/" + id, { reason: reason, initiated_by: "operator"});
    let action = mapEnforcementAction(row);
    return action;
  },

  unquarantineDevice: async (id: string): Promise<EnforcementAction> => {
    let row = await httpPost<BackendEnforcementAction>("/enforcement/release/" + id, {initiated_by: "operator"});
    let action = mapEnforcementAction(row);
    return action;
  },

  /**
   *  fetches enforcement history
   *  used by controls screen tsx
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

/*
* real time websocket connection
*/
  connectRealtime: () => {
    if (ws) 
    {
      return;
    }

    ws = new WebSocket(wsUrl());

    ws.onopen = () => {
      listeners.forEach((listener) => listener({ type: "WS_OPEN" }));
    };

    ws.onclose = () => {
      listeners.forEach((listener) => listener({ type: "WS_CLOSED" }));
      ws = null;
    };

    ws.onerror = () => {
      listeners.forEach((listener) => listener({ type: "WS_ERROR" }));
    };

    ws.onmessage = (message) => {
      try {
        let parsedMessage = JSON.parse(String(message.data));

        if (!parsedMessage) {
          return;
        }

        if (
          (parsedMessage.event === "alert.created" || parsedMessage.event === "alert.updated") && parsedMessage.payload) 
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

      if (parsedMessage.event === "alert.resolved" && parsedMessage.payload) {
        let alert = mapAlert(parsedMessage.payload as BackendAlert);

        listeners.forEach((listener) => {
          listener({
            type: "ALERT_RESOLVED",
            payload: alert
          });
        });

        return;
      }

      if (
        (parsedMessage.event === "device.quarantined" || parsedMessage.event === "device.released" || parsedMessage.event === "device.monitor_only") && parsedMessage.payload ) 
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

      listeners.forEach((listener) => {
        listener({
          type: "WS_EVENT",
          event: parsedMessage.event,
          payload: parsedMessage.payload
        });
      });
    } catch (error) {
    }
};  },

  disconnectRealtime: () => {
    if (ws) 
    {
      ws.close();
    }
    ws = null;
  },

  subscribe: (listener: Listener) => {
    listeners.push(listener);

    return () => {
      listeners = listeners.filter((currentListener) => {
        return currentListener !== listener;
      });
   };
  }
};
