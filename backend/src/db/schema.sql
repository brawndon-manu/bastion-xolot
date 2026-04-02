CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    mac_address TEXT,
    ip_address TEXT,
    hostname TEXT,
    first_seen INTEGER,
    last_seen INTEGER,
    risk_score INTEGER DEFAULT 0,
    status TEXT DEFAULT 'normal'
);

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    device_id TEXT,
    type TEXT,
    timestamp INTEGER,
    data TEXT,
    FOREIGN KEY(device_id) REFERENCES devices(id)
);

CREATE TABLE IF NOT EXISTS metadata_summaries (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    source_event_id TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    window_end INTEGER NOT NULL,
    flow_count INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0,
    unique_destinations INTEGER DEFAULT 0,
    blocked_dns INTEGER DEFAULT 0,
    suspicious_connections INTEGER DEFAULT 0,
    ids_alerts INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(device_id) REFERENCES devices(id),
    FOREIGN KEY(source_event_id) REFERENCES events(id)
);

CREATE TABLE IF NOT EXISTS device_baselines (
    device_id TEXT PRIMARY KEY,
    avg_flow_count REAL DEFAULT 0,
    avg_total_bytes REAL DEFAULT 0,
    avg_unique_destinations REAL DEFAULT 0,
    sample_count INTEGER DEFAULT 0,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY(device_id) REFERENCES devices(id)
);

CREATE TABLE IF NOT EXISTS anomalies (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    source_event_id TEXT NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    score REAL NOT NULL,
    summary TEXT NOT NULL,
    evidence TEXT,
    status TEXT DEFAULT 'open',
    created_at INTEGER NOT NULL,
    FOREIGN KEY(device_id) REFERENCES devices(id),
    FOREIGN KEY(source_event_id) REFERENCES events(id)
);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    device_id TEXT,
    type TEXT,
    severity TEXT,
    title TEXT,
    explanation TEXT,
    evidence TEXT,
    confidence REAL,
    status TEXT DEFAULT 'active',
    created_at INTEGER,
    FOREIGN KEY(device_id) REFERENCES devices(id)
);

CREATE TABLE IF NOT EXISTS enforcement_actions (
    id TEXT PRIMARY KEY,
    device_id TEXT,
    action TEXT,
    reason TEXT,
    initiated_by TEXT,
    created_at TIMESTAMP,
    mode TEXT DEFAULT 'active',
    status TEXT DEFAULT 'applied',
    evidence TEXT,
    FOREIGN KEY(device_id) REFERENCES devices(id)
);

CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_device_id ON alerts(device_id);
CREATE INDEX IF NOT EXISTS idx_events_device_id ON events(device_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_metadata_device_id ON metadata_summaries(device_id);
CREATE INDEX IF NOT EXISTS idx_metadata_created_at ON metadata_summaries(created_at);
CREATE INDEX IF NOT EXISTS idx_anomalies_device_id ON anomalies(device_id);
CREATE INDEX IF NOT EXISTS idx_anomalies_created_at ON anomalies(created_at);