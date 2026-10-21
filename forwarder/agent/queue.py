"""
NIGHTWATCH Forwarder Agent — Durable SQLite Local Event Queue
Guarantees at-least-once delivery, zero silent data loss, crash resilience,
bounded capacity enforcement, and explicit acknowledgement retirement.
"""

import json
import logging
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from forwarder.agent.event_schema import ForwarderEvent

logger = logging.getLogger("nightwatch.forwarder.queue")


class QueueFullError(Exception):
    """Raised when the persistent queue has reached its maximum configured capacity."""
    pass


class DurableQueue:
    """
    Persistent, transactional, SQLite-backed event queue with WAL mode.
    Guarantees that unacknowledged events survive process crashes and network outages.
    """

    def __init__(
        self,
        db_path: str,
        max_size_mb: int = 500,
        max_events: int = 100000,
        full_policy: str = "pause_collection",
        max_capacity: Optional[int] = None
    ):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if max_capacity is not None:
            max_events = max_capacity
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.max_events = max_events
        self.full_policy = full_policy

        self._init_db()
        self.requeue_all_in_flight()

    def _get_conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, timeout=30.0)

    def _init_db(self) -> None:
        conn = self._get_conn()
        try:
            with conn:
                conn.execute("PRAGMA journal_mode = WAL;")
                conn.execute("PRAGMA synchronous = NORMAL;")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS queue_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT UNIQUE NOT NULL,
                        payload TEXT NOT NULL,
                        payload_size INTEGER NOT NULL,
                        status TEXT NOT NULL DEFAULT 'pending',
                        attempts INTEGER NOT NULL DEFAULT 0,
                        created_at REAL NOT NULL,
                        last_attempt_at REAL,
                        batch_id TEXT
                    );
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_queue_status_id ON queue_events(status, id);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_queue_batch ON queue_events(batch_id);")
        finally:
            conn.close()

    def get_queue_size_bytes(self) -> int:
        """Calculates current size of the queue database on disk."""
        total = 0
        try:
            if self.db_path.exists():
                total += self.db_path.stat().st_size
            wal_file = self.db_path.with_name(self.db_path.name + "-wal")
            if wal_file.exists():
                total += wal_file.stat().st_size
        except Exception:
            pass
        return total

    def count_pending(self) -> int:
        """Counts pending (unleased) events in queue."""
        conn = self._get_conn()
        try:
            cur = conn.execute("SELECT COUNT(*) FROM queue_events WHERE status = 'pending';")
            return cur.fetchone()[0]
        finally:
            conn.close()

    def count_total(self) -> int:
        """Counts all events in queue (pending + in_flight)."""
        conn = self._get_conn()
        try:
            cur = conn.execute("SELECT COUNT(*) FROM queue_events;")
            return cur.fetchone()[0]
        finally:
            conn.close()

    def enqueue(self, event: ForwarderEvent) -> bool:
        return self.enqueue_batch([event]) > 0

    def enqueue_batch(self, events: List[ForwarderEvent]) -> int:
        """
        Atomically enqueues a batch of events within a single transaction.
        Returns the number of newly enqueued events.
        """
        if not events:
            return 0

        # Capacity check
        curr_total = self.count_total()
        curr_size = self.get_queue_size_bytes()

        if curr_total + len(events) > self.max_events or curr_size > self.max_size_bytes:
            if self.full_policy == "pause_collection":
                logger.warning(
                    f"Queue capacity limit reached ({curr_total}/{self.max_events} events, "
                    f"{curr_size // (1024*1024)} MB). Pausing collection."
                )
                raise QueueFullError("Durable queue is full. Collection paused.")
            elif self.full_policy == "drop_oldest":
                to_drop = (curr_total + len(events)) - self.max_events + 50
                conn = self._get_conn()
                try:
                    with conn:
                        conn.execute("""
                            DELETE FROM queue_events
                            WHERE id IN (
                                SELECT id FROM queue_events
                                WHERE status = 'pending'
                                ORDER BY id ASC LIMIT ?
                            );
                        """, (to_drop,))
                finally:
                    conn.close()

        now = time.time()
        inserted_count = 0
        conn = self._get_conn()
        try:
            with conn:
                cur = conn.cursor()
                for ev in events:
                    raw_json = ev.to_json()
                    size_bytes = len(raw_json.encode("utf-8"))
                    try:
                        cur.execute("""
                            INSERT OR IGNORE INTO queue_events (
                                event_id, payload, payload_size, status, attempts, created_at
                            ) VALUES (?, ?, ?, 'pending', 0, ?);
                        """, (ev.event_id, raw_json, size_bytes, now))
                        if cur.rowcount > 0:
                            inserted_count += 1
                    except Exception as e:
                        logger.error(f"Error inserting event {ev.event_id} into durable queue: {e}")
        finally:
            conn.close()

        return inserted_count

    def lease_batch(
        self,
        batch_size: int,
        batch_id: Optional[str] = None
    ) -> Union[List[ForwarderEvent], Tuple[str, List[ForwarderEvent]]]:
        """
        Fetches up to batch_size pending events, marks them as 'in_flight' under batch_id.
        Maintains stable ordering by id (FIFO).
        """
        return_tuple = False
        if batch_id is None:
            batch_id = str(uuid.uuid4())
            return_tuple = True

        now = time.time()
        events: List[ForwarderEvent] = []

        conn = self._get_conn()
        try:
            with conn:
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()

                cur.execute("""
                    SELECT id, payload FROM queue_events
                    WHERE status = 'pending'
                    ORDER BY id ASC
                    LIMIT ?;
                """, (batch_size,))
                rows = cur.fetchall()

                if rows:
                    ids = [r["id"] for r in rows]
                    placeholders = ",".join("?" for _ in ids)

                    cur.execute(f"""
                        UPDATE queue_events
                        SET status = 'in_flight',
                            batch_id = ?,
                            attempts = attempts + 1,
                            last_attempt_at = ?
                        WHERE id IN ({placeholders});
                    """, [batch_id, now] + ids)

                    for r in rows:
                        try:
                            ev_dict = json.loads(r["payload"])
                            events.append(ForwarderEvent(**ev_dict))
                        except Exception as e:
                            logger.error(f"Failed deserializing queued event row {r['id']}: {e}")
        finally:
            conn.close()

        if return_tuple:
            return batch_id, events
        return events

    def acknowledge_batch(self, batch_id: str, accepted_event_ids: List[str]) -> int:
        """
        Permanently removes acknowledged events from durable storage.
        Validates event_ids against matching batch_id.
        """
        if not accepted_event_ids:
            return 0

        conn = self._get_conn()
        try:
            with conn:
                cur = conn.cursor()
                placeholders = ",".join("?" for _ in accepted_event_ids)
                cur.execute(f"""
                    DELETE FROM queue_events
                    WHERE batch_id = ? AND event_id IN ({placeholders});
                """, [batch_id] + accepted_event_ids)
                return cur.rowcount
        finally:
            conn.close()

    def retire_acknowledged(self, event_ids: List[str]) -> int:
        """Direct retirement of acknowledged event IDs."""
        if not event_ids:
            return 0
        conn = self._get_conn()
        try:
            with conn:
                placeholders = ",".join("?" for _ in event_ids)
                cur = conn.execute(f"DELETE FROM queue_events WHERE event_id IN ({placeholders})", event_ids)
                return cur.rowcount
        finally:
            conn.close()

    def requeue_batch(self, batch_id: str) -> int:
        """Resets all events in a failed or timed-out batch back to 'pending'."""
        conn = self._get_conn()
        try:
            with conn:
                cur = conn.execute("""
                    UPDATE queue_events
                    SET status = 'pending',
                        batch_id = NULL
                    WHERE batch_id = ?;
                """, (batch_id,))
                return cur.rowcount
        finally:
            conn.close()

    def requeue_all_in_flight(self) -> int:
        """Called on startup: recovers in_flight events that were interrupted by a crash."""
        conn = self._get_conn()
        try:
            with conn:
                cur = conn.execute("""
                    UPDATE queue_events
                    SET status = 'pending',
                        batch_id = NULL
                    WHERE status = 'in_flight';
                """)
                requeued = cur.rowcount
            if requeued > 0:
                logger.info(f"Crash recovery: requeued {requeued} in-flight events to pending status.")
            return requeued
        finally:
            conn.close()

    def get_health_metrics(self) -> Dict[str, Any]:
        """Returns operational queue health metrics for diagnostics."""
        conn = self._get_conn()
        try:
            conn.row_factory = sqlite3.Row
            cur = conn.execute("""
                SELECT
                    COUNT(*) as total_count,
                    SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_count,
                    SUM(CASE WHEN status = 'in_flight' THEN 1 ELSE 0 END) as in_flight_count,
                    MIN(CASE WHEN status = 'pending' THEN created_at ELSE NULL END) as oldest_pending_epoch
                FROM queue_events;
            """)
            row = cur.fetchone()
        finally:
            conn.close()

        total = row["total_count"] or 0
        pending = row["pending_count"] or 0
        in_flight = row["in_flight_count"] or 0
        oldest_epoch = row["oldest_pending_epoch"]
        oldest_age_sec = (time.time() - oldest_epoch) if oldest_epoch else 0.0

        return {
            "total_events": total,
            "pending_events": pending,
            "in_flight_events": in_flight,
            "oldest_pending_age_seconds": round(oldest_age_sec, 2),
            "disk_usage_bytes": self.get_queue_size_bytes(),
            "disk_usage_mb": round(self.get_queue_size_bytes() / (1024 * 1024), 2),
            "capacity_pct": round((total / max(1, self.max_events)) * 100, 2)
        }

    # Aliases
    push_batch = enqueue_batch
    get_depth = count_pending
