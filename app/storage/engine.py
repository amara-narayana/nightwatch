"""
NIGHTWATCH — Persistent Storage Engine (SQLite + FTS5)
"""

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import get_settings
from app.models.alert import SecurityAlert
from app.models.event import NormalizedEvent


class StorageEngine:
    def __init__(self, db_path: Optional[str] = None):
        settings = get_settings()
        self.db_path = settings.resolve_path(db_path or settings.storage.db_path)
        # Ensure parent directory exists
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        """Creates an optimized SQLite connection with WAL mode and custom pragma settings."""
        conn = sqlite3.connect(
            self.db_path,
            timeout=10.0,
            check_same_thread=False
        )
        conn.row_factory = sqlite3.Row
        # Performance PRAGMAs tailored for 8GB RAM local storage
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA cache_size = -32000;")  # 32 MB cache
        conn.execute("PRAGMA temp_store = MEMORY;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        return conn

    def init_db(self) -> None:
        """Initializes tables, indexes, FTS5 virtual tables, and triggers."""
        with self.get_connection() as conn:
            # 1. Main Events Table
            conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                epoch REAL NOT NULL,
                index_name TEXT NOT NULL,
                host TEXT NOT NULL,
                source TEXT NOT NULL,
                sourcetype TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                raw TEXT NOT NULL,
                fields_json TEXT NOT NULL
            );
            """)

            # 2. Performance B-Tree Indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_epoch ON events(epoch);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_index ON events(index_name);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_sourcetype ON events(sourcetype);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_composite ON events(index_name, epoch DESC);")

            # 3. FTS5 Virtual Table for Sub-Second Full-Text Queries
            conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
                raw,
                content='events',
                content_rowid='id',
                tokenize='unicode61 remove_diacritics 2'
            );
            """)

            # 4. FTS5 Synchronization Triggers
            conn.execute("""
            CREATE TRIGGER IF NOT EXISTS events_ai AFTER INSERT ON events BEGIN
                INSERT INTO events_fts(rowid, raw) VALUES (new.id, new.raw);
            END;
            """)
            conn.execute("""
            CREATE TRIGGER IF NOT EXISTS events_ad AFTER DELETE ON events BEGIN
                INSERT INTO events_fts(events_fts, rowid, raw) VALUES('delete', old.id, old.raw);
            END;
            """)

            # 5. Checkpoints Table for Ingestion Tracking
            conn.execute("""
            CREATE TABLE IF NOT EXISTS checkpoints (
                source_path TEXT PRIMARY KEY,
                inode INTEGER,
                device INTEGER,
                last_offset INTEGER NOT NULL,
                file_size INTEGER NOT NULL,
                header_hash TEXT NOT NULL,
                last_modified REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            """)

            # 6. Security Alerts Table
            conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT NOT NULL,
                triggered_at TEXT NOT NULL,
                triggered_epoch REAL NOT NULL,
                status TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                evidence_json TEXT NOT NULL,
                resolution_notes TEXT,
                updated_at REAL NOT NULL
            );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_epoch ON alerts(triggered_epoch DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);")

            # 7. Saved Searches Table
            conn.execute("""
            CREATE TABLE IF NOT EXISTS saved_searches (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                query TEXT NOT NULL,
                description TEXT,
                created_at REAL NOT NULL,
                last_run_at REAL,
                run_count INTEGER DEFAULT 0
            );
            """)

            # 8. Search History Table
            conn.execute("""
            CREATE TABLE IF NOT EXISTS search_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                query TEXT NOT NULL,
                executed_at REAL NOT NULL,
                duration_ms REAL NOT NULL,
                result_count INTEGER NOT NULL,
                status TEXT NOT NULL
            );
            """)

    def insert_events_batch(self, events: List[NormalizedEvent]) -> int:
        """Inserts a batch of normalized events atomically."""
        if not events:
            return 0

        rows = []
        for e in events:
            fields_str = json.dumps(e.fields, separators=(',', ':'))
            rows.append((
                e.timestamp,
                e.epoch,
                e.index_name,
                e.host,
                e.source,
                e.sourcetype,
                e.severity,
                e.category,
                e.raw,
                fields_str
            ))

        with self.get_connection() as conn:
            conn.executemany("""
                INSERT INTO events (
                    timestamp, epoch, index_name, host, source,
                    sourcetype, severity, category, raw, fields_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, rows)
            count = len(rows)

        return count

    def get_event_by_id(self, event_id: int) -> Optional[NormalizedEvent]:
        """Retrieves an event by its primary key ID."""
        with self.get_connection() as conn:
            cur = conn.execute("SELECT * FROM events WHERE id = ?;", (event_id,))
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_event(row)

    def _row_to_event(self, row: sqlite3.Row) -> NormalizedEvent:
        fields = {}
        if row["fields_json"]:
            try:
                fields = json.loads(row["fields_json"])
            except Exception:
                fields = {}

        return NormalizedEvent(
            id=row["id"],
            timestamp=row["timestamp"],
            epoch=row["epoch"],
            index_name=row["index_name"],
            host=row["host"],
            source=row["source"],
            sourcetype=row["sourcetype"],
            severity=row["severity"],
            category=row["category"],
            raw=row["raw"],
            fields=fields
        )

    def count_events(self, where_clause: str = "", params: tuple = ()) -> int:
        """Returns count of events matching criteria."""
        sql = "SELECT COUNT(*) as cnt FROM events"
        if where_clause:
            sql += f" WHERE {where_clause}"
        with self.get_connection() as conn:
            cur = conn.execute(sql, params)
            return cur.fetchone()["cnt"]

    # --- Checkpoints Management ---

    def save_checkpoint(
        self,
        source_path: str,
        inode: int,
        device: int,
        last_offset: int,
        file_size: int,
        header_hash: str,
        last_modified: float
    ) -> None:
        now = time.time()
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO checkpoints (
                    source_path, inode, device, last_offset, file_size,
                    header_hash, last_modified, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_path) DO UPDATE SET
                    inode = excluded.inode,
                    device = excluded.device,
                    last_offset = excluded.last_offset,
                    file_size = excluded.file_size,
                    header_hash = excluded.header_hash,
                    last_modified = excluded.last_modified,
                    updated_at = excluded.updated_at;
            """, (source_path, inode, device, last_offset, file_size, header_hash, last_modified, now))

    def get_checkpoint(self, source_path: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cur = conn.execute("SELECT * FROM checkpoints WHERE source_path = ?;", (source_path,))
            row = cur.fetchone()
            if not row:
                return None
            return dict(row)

    def get_all_checkpoints(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cur = conn.execute("SELECT * FROM checkpoints ORDER BY updated_at DESC;")
            return [dict(r) for r in cur.fetchall()]

    # --- Alert Storage Operations ---

    def insert_alert(self, alert: SecurityAlert) -> None:
        evidence_str = json.dumps(alert.evidence, separators=(',', ':'))
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO alerts (
                    id, rule_id, rule_name, severity, category, description,
                    triggered_at, triggered_epoch, status, event_count,
                    evidence_json, resolution_notes, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                alert.id, alert.rule_id, alert.rule_name, alert.severity,
                alert.category, alert.description, alert.triggered_at,
                alert.triggered_epoch, alert.status, alert.event_count,
                evidence_str, alert.resolution_notes, alert.updated_at
            ))

    def get_alerts(self, status: Optional[str] = None, limit: int = 100) -> List[SecurityAlert]:
        with self.get_connection() as conn:
            if status:
                cur = conn.execute(
                    "SELECT * FROM alerts WHERE status = ? ORDER BY triggered_epoch DESC LIMIT ?;",
                    (status, limit)
                )
            else:
                cur = conn.execute(
                    "SELECT * FROM alerts ORDER BY triggered_epoch DESC LIMIT ?;",
                    (limit,)
                )
            results = []
            for row in cur.fetchall():
                evidence = []
                if row["evidence_json"]:
                    try:
                        evidence = json.loads(row["evidence_json"])
                    except Exception:
                        evidence = []
                results.append(SecurityAlert(
                    id=row["id"],
                    rule_id=row["rule_id"],
                    rule_name=row["rule_name"],
                    severity=row["severity"],
                    category=row["category"],
                    description=row["description"],
                    triggered_at=row["triggered_at"],
                    triggered_epoch=row["triggered_epoch"],
                    status=row["status"],
                    event_count=row["event_count"],
                    evidence=evidence,
                    resolution_notes=row["resolution_notes"],
                    updated_at=row["updated_at"]
                ))
            return results

    def get_alert_by_id(self, alert_id: str) -> Optional[SecurityAlert]:
        with self.get_connection() as conn:
            cur = conn.execute("SELECT * FROM alerts WHERE id = ?;", (alert_id,))
            row = cur.fetchone()
            if not row:
                return None
            evidence = []
            if row["evidence_json"]:
                try:
                    evidence = json.loads(row["evidence_json"])
                except Exception:
                    evidence = []
            return SecurityAlert(
                id=row["id"],
                rule_id=row["rule_id"],
                rule_name=row["rule_name"],
                severity=row["severity"],
                category=row["category"],
                description=row["description"],
                triggered_at=row["triggered_at"],
                triggered_epoch=row["triggered_epoch"],
                status=row["status"],
                event_count=row["event_count"],
                evidence=evidence,
                resolution_notes=row["resolution_notes"],
                updated_at=row["updated_at"]
            )

    def update_alert_status(self, alert_id: str, status: str, notes: Optional[str] = None) -> bool:
        now = time.time()
        with self.get_connection() as conn:
            if notes is not None:
                cur = conn.execute(
                    "UPDATE alerts SET status = ?, resolution_notes = ?, updated_at = ? WHERE id = ?;",
                    (status, notes, now, alert_id)
                )
            else:
                cur = conn.execute(
                    "UPDATE alerts SET status = ?, updated_at = ? WHERE id = ?;",
                    (status, now, alert_id)
                )
            return cur.rowcount > 0

    def check_recent_alert_exists(self, rule_id: str, since_epoch: float) -> bool:
        """Used for alert suppression window deduplication."""
        with self.get_connection() as conn:
            cur = conn.execute(
                "SELECT 1 FROM alerts WHERE rule_id = ? AND triggered_epoch >= ? LIMIT 1;",
                (rule_id, since_epoch)
            )
            return cur.fetchone() is not None

    # --- Retention & Database Maintenance ---

    def get_db_size_mb(self) -> float:
        """Returns total on-disk size of the SQLite DB including WAL and SHM files."""
        total_bytes = 0
        p = Path(self.db_path)
        if p.exists():
            total_bytes += p.stat().st_size
        wal = Path(str(self.db_path) + "-wal")
        if wal.exists():
            total_bytes += wal.stat().st_size
        shm = Path(str(self.db_path) + "-shm")
        if shm.exists():
            total_bytes += shm.stat().st_size
        return round(total_bytes / (1024 * 1024), 2)

    def delete_events_older_than(self, cutoff_epoch: float) -> int:
        """Deletes events older than cutoff epoch."""
        with self.get_connection() as conn:
            cur = conn.execute("DELETE FROM events WHERE epoch < ?;", (cutoff_epoch,))
            return cur.rowcount

    def prune_oldest_events(self, count_to_prune: int) -> int:
        """Prunes the oldest N events when storage budget is exceeded."""
        with self.get_connection() as conn:
            cur = conn.execute("""
                DELETE FROM events WHERE id IN (
                    SELECT id FROM events ORDER BY epoch ASC LIMIT ?
                );
            """, (count_to_prune,))
            return cur.rowcount

    def run_vacuum(self) -> None:
        """Executes VACUUM to reclaim space."""
        # VACUUM cannot be run within a transaction
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("VACUUM;")
        finally:
            conn.close()


_storage_instance: Optional[StorageEngine] = None


def get_storage_engine() -> StorageEngine:
    global _storage_instance
    if _storage_instance is None:
        _storage_instance = StorageEngine()
    return _storage_instance
