"""
Bastión Xólot — Local Agent Storage

SQLite database for the edge agent running on the Raspberry Pi.
Stores discovered devices, queued events, and DNS block records
locally so the agent can operate even when the backend is unreachable.

This is separate from the backend's SQLite database — the agent
owns this store; the backend owns its own.
"""

import sqlite3
import json
import logging
from pathlib import Path
from typing import Optional

from bastion_agent.config import LOCAL_DB_PATH
from bastion_agent.utils import utcnow_iso

logger = logging.getLogger(__name__)

# ── Module-level connection ──
_conn: Optional[sqlite3.Connection] = None


# ─────────────────────────────────────────────
# Schema (auto-applied on first run / reboot)
# ─────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS known_devices (
    mac_address  TEXT PRIMARY KEY,
    ip_address   TEXT NOT NULL,
    hostname     TEXT,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS event_queue (
    id           TEXT PRIMARY KEY,
    event_json   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    dispatched   INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS dns_blocks (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    domain       TEXT NOT NULL,
    client_ip    TEXT NOT NULL,
    client_mac   TEXT,
    timestamp    TEXT NOT NULL,
    alerted      INTEGER DEFAULT 0
);
"""


# ─────────────────────────────────────────────
# Initialization
# ─────────────────────────────────────────────

def init_local_db(db_path: str | None = None) -> sqlite3.Connection:
    """
    Open (or create) the agent's local SQLite database and apply schema.

    Must be called once at agent startup.
    """
    global _conn

    path = db_path or LOCAL_DB_PATH
    db_dir = Path(path).parent
    db_dir.mkdir(parents=True, exist_ok=True)

    _conn = sqlite3.connect(path)
    _conn.row_factory = sqlite3.Row
    _conn.execute("PRAGMA journal_mode = WAL")
    _conn.execute("PRAGMA foreign_keys = ON")
    _conn.executescript(_SCHEMA)
    _conn.commit()

    logger.info("Local agent database initialized at %s", path)
    return _conn


def get_conn() -> sqlite3.Connection:
    """Return the active database connection (fails fast if not initialized)."""
    if _conn is None:
        raise RuntimeError("Local database not initialized — call init_local_db() first")
    return _conn


# ─────────────────────────────────────────────
# Device tracking
# ─────────────────────────────────────────────

def get_known_device(mac: str) -> Optional[dict]:
    """Fetch a previously-seen device by MAC address, or None."""
    row = get_conn().execute(
        "SELECT * FROM known_devices WHERE mac_address = ?", (mac,)
    ).fetchone()
    return dict(row) if row else None


def upsert_device(mac: str, ip: str, hostname: str | None = None) -> bool:
    """
    Insert or update a device record.

    Returns True if this is the first time the device has been seen
    (new device), False if it was already known.
    """
    now = utcnow_iso()
    existing = get_known_device(mac)

    if existing:
        get_conn().execute(
            "UPDATE known_devices SET ip_address = ?, hostname = COALESCE(?, hostname), last_seen = ? "
            "WHERE mac_address = ?",
            (ip, hostname, now, mac),
        )
        get_conn().commit()
        return False  # already known
    else:
        get_conn().execute(
            "INSERT INTO known_devices (mac_address, ip_address, hostname, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?)",
            (mac, ip, hostname, now, now),
        )
        get_conn().commit()
        return True  # new device


def get_all_known_devices() -> list[dict]:
    """Return all known devices as a list of dicts."""
    rows = get_conn().execute("SELECT * FROM known_devices").fetchall()
    return [dict(r) for r in rows]


# ─────────────────────────────────────────────
# Event queue (for dispatch to backend)
# ─────────────────────────────────────────────

def enqueue_event(event_id: str, event_dict: dict) -> None:
    """Store an event locally for later dispatch to the backend."""
    get_conn().execute(
        "INSERT OR IGNORE INTO event_queue (id, event_json, created_at) VALUES (?, ?, ?)",
        (event_id, json.dumps(event_dict), utcnow_iso()),
    )
    get_conn().commit()


def get_pending_events(limit: int = 50) -> list[dict]:
    """Retrieve events that have not yet been dispatched."""
    rows = get_conn().execute(
        "SELECT id, event_json FROM event_queue WHERE dispatched = 0 ORDER BY created_at ASC LIMIT ?",
        (limit,),
    ).fetchall()
    return [{"id": row["id"], **json.loads(row["event_json"])} for row in rows]


def mark_events_dispatched(event_ids: list[str]) -> None:
    """Mark a batch of events as successfully dispatched."""
    if not event_ids:
        return
    placeholders = ",".join("?" for _ in event_ids)
    get_conn().execute(
        f"UPDATE event_queue SET dispatched = 1 WHERE id IN ({placeholders})",
        event_ids,
    )
    get_conn().commit()


# ─────────────────────────────────────────────
# DNS block records
# ─────────────────────────────────────────────

def record_dns_block(
    domain: str, client_ip: str, client_mac: str | None = None, timestamp: str | None = None
) -> int:
    """
    Record a blocked DNS query locally.
    Returns the row ID of the new record.
    """
    ts = timestamp or utcnow_iso()
    cursor = get_conn().execute(
        "INSERT INTO dns_blocks (domain, client_ip, client_mac, timestamp) VALUES (?, ?, ?, ?)",
        (domain, client_ip, client_mac, ts),
    )
    get_conn().commit()
    return cursor.lastrowid  # type: ignore[return-value]


def get_unalerted_dns_blocks(limit: int = 100) -> list[dict]:
    """Get DNS blocks that haven't been converted to alerts yet."""
    rows = get_conn().execute(
        "SELECT * FROM dns_blocks WHERE alerted = 0 ORDER BY timestamp ASC LIMIT ?",
        (limit,),
    ).fetchall()
    return [dict(r) for r in rows]


def mark_dns_blocks_alerted(row_ids: list[int]) -> None:
    """Mark DNS block records as having been alerted on."""
    if not row_ids:
        return
    placeholders = ",".join("?" for _ in row_ids)
    get_conn().execute(
        f"UPDATE dns_blocks SET alerted = 1 WHERE id IN ({placeholders})",
        row_ids,
    )
    get_conn().commit()
