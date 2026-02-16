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
    FOREIGN KEY(device_id) REFERENCES devices(id)
);

CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_device_id ON alerts(device_id);
CREATE INDEX IF NOT EXISTS idx_events_device_id ON events(device_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);