"""
NIGHTWATCH Forwarder Receiver — Event Deduplication Engine
Provides durable, idempotent event deduplication using stable event IDs.
Prevents duplicate ingestion when agents retry unacknowledged transmissions.
"""

import logging
import sqlite3
from typing import Any, Dict, List, Set, Tuple

logger = logging.getLogger("nightwatch.forwarder.receiver.dedup")


class DeduplicationEngine:
    """
    Checks incoming event batches against already persisted event IDs.
    Returns partitioned new events and duplicate IDs.
    """

    def __init__(self, cache_size: int = 50000):
        # LRU/FIFO in-memory cache of recently observed event_ids for fast filtering
        self._cache_size = cache_size
        self._recent_ids: Set[str] = set()
        self._recent_queue: List[str] = []

    def record_seen(self, event_ids: List[str]) -> None:
        """Caches event IDs to avoid repeated database lookups."""
        for eid in event_ids:
            if eid not in self._recent_ids:
                self._recent_ids.add(eid)
                self._recent_queue.append(eid)
        # Trim cache if needed
        if len(self._recent_queue) > self._cache_size:
            excess = len(self._recent_queue) - self._cache_size
            for _ in range(excess):
                old = self._recent_queue.pop(0)
                self._recent_ids.discard(old)

    def partition_batch(
        self,
        events: List[Dict[str, Any]],
        conn: sqlite3.Connection
    ) -> Tuple[List[Dict[str, Any]], List[str]]:
        """
        Partitions incoming events into:
          - new_events: List of event dicts that have NOT been committed yet
          - duplicate_ids: List of event_id strings that already exist in storage
        """
        if not events:
            return [], []

        all_ids = [e["event_id"] for e in events]
        duplicate_ids: Set[str] = set()

        # 1. Quick in-memory cache check
        candidate_ids = []
        for eid in all_ids:
            if eid in self._recent_ids:
                duplicate_ids.add(eid)
            else:
                candidate_ids.append(eid)

        # 2. Database verification for candidates
        if candidate_ids:
            # Query in chunks to respect SQLite variable limits
            chunk_size = 500
            for i in range(0, len(candidate_ids), chunk_size):
                chunk = candidate_ids[i:i + chunk_size]
                placeholders = ",".join(["?"] * len(chunk))
                cursor = conn.execute(
                    f"SELECT event_id FROM events WHERE event_id IN ({placeholders})",
                    chunk
                )
                for (found_id,) in cursor.fetchall():
                    duplicate_ids.add(found_id)
                    self._recent_ids.add(found_id)

        # 3. Partition events
        new_events: List[Dict[str, Any]] = []
        seen_in_this_batch: Set[str] = set()

        for e in events:
            eid = e["event_id"]
            if eid in duplicate_ids or eid in seen_in_this_batch:
                duplicate_ids.add(eid)
            else:
                seen_in_this_batch.add(eid)
                new_events.append(e)

        return new_events, list(duplicate_ids)
