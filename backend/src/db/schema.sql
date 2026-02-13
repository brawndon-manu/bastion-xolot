CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    mac_address TEXT,
    ip_address TEXT
    hostname TEXT,
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    risk_score INTEGER DEFAULT 0,
    status TEXT DEFAULT 'normal'
);

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    device_id TEXT,
    type TEXT,
    timestamp TIMESTAMP,
    data TEXT,
    FOREIGN KEY(device_id) REFERENCES devices(id)
);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    device_id TEXT,
    severity TEXT,
    title TEXT,
    explanation TEXT,
    evidence TEXT,
    confidence REAL,
    status TEXT DEFAULT 'active',
    created_at TIMESTAMP,
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