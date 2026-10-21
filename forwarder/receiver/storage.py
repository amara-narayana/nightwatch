"""
NIGHTWATCH Forwarder Receiver — Durable Storage & Pipeline Sink
Persists accepted endpoint events to a durable SQLite store and replicates
records into the central NIGHTWATCH search engine (data/nightwatch.db).
"""

import datetime
import json
import logging
import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Tuple

from forwarder.receiver.config import ReceiverConfig
from forwarder.receiver.deduplication import DeduplicationEngine

logger = logging.getLogger("nightwatch.forwarder.receiver.storage")


class ReceiverStorage:
    """
    Manages durable event persistence, deduplication, and integration
    with the primary NIGHTWATCH search storage engine.
    """

    def __init__(self, config: ReceiverConfig):
        self.config = config
        self._db_path = config.storage_path
        self._nightwatch_db_path = config.nightwatch_db_path if config.integrate_nightwatch_db else None
        self._lock = threading.Lock()
        self.dedup = DeduplicationEngine()

        os.makedirs(os.path.dirname(os.path.abspath(self._db_path)), exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        return conn

    def _init_db(self) -> None:
        conn = self._get_connection()
        try:
            with conn:
                conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    source_name TEXT NOT NULL,
                    event_timestamp TEXT NOT NULL,
                    observed_timestamp TEXT NOT NULL,
                    received_timestamp TEXT NOT NULL,
                    message TEXT NOT NULL,
                    severity TEXT,
                    source_event_id TEXT,
                    source_record_id INTEGER,
                    metadata_json TEXT,
                    batch_id TEXT
                );
                """)

                conn.execute("""
                CREATE TABLE IF NOT EXISTS batches (
                    batch_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    event_count INTEGER NOT NULL,
                    received_at TEXT NOT NULL
                );
                """)

                conn.execute("CREATE INDEX IF NOT EXISTS idx_rev_agent_time ON events(agent_id, event_timestamp);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_rev_time ON events(event_timestamp);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_rev_source ON events(source_name);")
        finally:
            conn.close()

        logger.info(f"Receiver durable storage initialized at: {self._db_path}")

    def commit_batch(
        self,
        batch_id: str,
        agent_id: str,
        events: List[Dict[str, Any]]
    ) -> Tuple[List[str], List[str]]:
        """
        Durably commits an incoming event batch with deduplication.
        Returns:
          (accepted_event_ids: List[str], duplicate_event_ids: List[str])
        """
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self._lock:
            conn = self._get_connection()
            try:
                # 1. Deduplicate batch
                new_events, duplicate_ids = self.dedup.partition_batch(events, conn)

                # 2. Durably insert new events
                if new_events:
                    rows = []
                    for e in new_events:
                        meta_str = json.dumps(e.get("metadata", {}), ensure_ascii=False) if e.get("metadata") else "{}"
                        rows.append((
                            e["event_id"],
                            e.get("schema_version", "1.0"),
                            agent_id,
                            e.get("hostname", "unknown"),
                            e.get("platform", "unknown"),
                            e.get("source_type", "unknown"),
                            e.get("source_name", "unknown"),
                            e.get("event_timestamp", now_iso),
                            e.get("observed_timestamp", now_iso),
                            now_iso,
                            e["message"],
                            e.get("severity"),
                            e.get("source_event_id"),
                            e.get("source_record_id"),
                            meta_str,
                            batch_id
                        ))

                    with conn:
                        conn.executemany("""
                        INSERT OR IGNORE INTO events (
                            event_id, schema_version, agent_id, hostname, platform,
                            source_type, source_name, event_timestamp, observed_timestamp,
                            received_timestamp, message, severity, source_event_id,
                            source_record_id, metadata_json, batch_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """, rows)

                        conn.execute("""
                        INSERT OR REPLACE INTO batches (batch_id, agent_id, event_count, received_at)
                        VALUES (?, ?, ?, ?);
                        """, (batch_id, agent_id, len(new_events), now_iso))

                    # Record accepted IDs in in-memory deduplication cache
                    accepted_ids = [e["event_id"] for e in new_events]
                    self.dedup.record_seen(accepted_ids)
                else:
                    accepted_ids = []
            finally:
                conn.close()

            # 3. Replicate new events to central NIGHTWATCH search engine (data/nightwatch.db)
            if new_events and self._nightwatch_db_path:
                self._replicate_to_nightwatch_db(new_events, agent_id)

        return accepted_ids, duplicate_ids

    def _replicate_to_nightwatch_db(self, events: List[Dict[str, Any]], agent_id: str) -> None:
        """
        Replicates new events directly into the central NIGHTWATCH search index.
        """
        if not os.path.exists(os.path.dirname(os.path.abspath(self._nightwatch_db_path))):
            return

        nw_conn = None
        try:
            nw_conn = sqlite3.connect(self._nightwatch_db_path, timeout=10.0)
            with nw_conn:
                nw_rows = []
                for e in events:
                    # Calculate epoch
                    try:
                        dt = datetime.datetime.fromisoformat(e["event_timestamp"])
                        epoch = dt.timestamp()
                    except Exception:
                        epoch = datetime.datetime.now(datetime.timezone.utc).timestamp()

                    fields = dict(e.get("metadata") or {})
                    fields["agent_id"] = agent_id
                    fields["forwarder_event_id"] = e["event_id"]
                    fields["platform"] = e.get("platform")
                    if e.get("source_event_id"):
                        fields["source_event_id"] = e["source_event_id"]
                    if e.get("source_record_id") is not None:
                        fields["source_record_id"] = e["source_record_id"]

                    nw_rows.append((
                        e.get("event_timestamp"),
                        epoch,
                        "main",
                        e.get("hostname", agent_id),
                        e.get("source_name", "endpoint_forwarder"),
                        e.get("source_type", "forwarder"),
                        e.get("severity") or "INFO",
                        "endpoint_telemetry",
                        e["message"],
                        json.dumps(fields, ensure_ascii=False)
                    ))

                nw_conn.executemany("""
                INSERT INTO events (
                    timestamp, epoch, index_name, host, source,
                    sourcetype, severity, category, raw, fields_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, nw_rows)
                logger.debug(f"Replicated {len(nw_rows)} events to NIGHTWATCH core: {self._nightwatch_db_path}")

        except Exception as e:
            # Replicating to central search must not fail the primary receiver persistence
            logger.warning(f"Failed to replicate events to central NIGHTWATCH db: {e}")
        finally:
            if nw_conn:
                try:
                    nw_conn.close()
                except Exception:
                    pass

    def query_events(
        self,
        agent_id: Optional[str] = None,
        source_name: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Queries stored events for verification and search."""
        query = "SELECT * FROM events"
        params: List[Any] = []
        conditions = []

        if agent_id:
            conditions.append("agent_id = ?")
            params.append(agent_id)
        if source_name:
            conditions.append("source_name = ?")
            params.append(source_name)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY event_timestamp DESC LIMIT ?"
        params.append(limit)

        conn = self._get_connection()
        try:
            cur = conn.execute(query, params)
            return [dict(row) for row in cur.fetchall()]
        finally:
            conn.close()

    def get_event_count(self) -> int:
        """Returns total count of persisted unique events."""
        conn = self._get_connection()
        try:
            cur = conn.execute("SELECT COUNT(*) FROM events;")
            return cur.fetchone()[0]
        finally:
            conn.close()
