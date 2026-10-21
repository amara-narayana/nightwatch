"""
Integration Tests for Receiver Storage and Core NIGHTWATCH Replication
"""

import json
import sqlite3
import tempfile
from pathlib import Path

from forwarder.receiver.config import ReceiverConfig
from forwarder.receiver.storage import ReceiverStorage


def test_receiver_storage_commit_and_deduplication():
    with tempfile.TemporaryDirectory() as td:
        db_path = str(Path(td) / "receiver.db")
        nw_db_path = str(Path(td) / "nightwatch.db")

        # Initialize mock central NIGHTWATCH DB
        conn = sqlite3.connect(nw_db_path)
        try:
            with conn:
                conn.execute("""
                CREATE TABLE events (
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
        finally:
            conn.close()

        cfg = ReceiverConfig(
            ca_cert_path="dummy.crt",
            server_cert_path="dummy.crt",
            server_key_path="dummy.key",
            storage_path=db_path,
            integrate_nightwatch_db=True,
            nightwatch_db_path=nw_db_path
        )

        storage = ReceiverStorage(cfg)

        events_batch = [
            {
                "schema_version": "1.0",
                "event_id": "ev-100",
                "agent_id": "agt-1",
                "hostname": "srv-01",
                "platform": "windows",
                "source_type": "wineventlog",
                "source_name": "System",
                "event_timestamp": "2026-10-21T12:00:00Z",
                "observed_timestamp": "2026-10-21T12:00:01Z",
                "message": "System time synchronized with NTP",
                "severity": "INFO",
                "source_event_id": "35",
                "source_record_id": 501,
                "metadata": {"provider": "Kernel-Time"}
            },
            {
                "schema_version": "1.0",
                "event_id": "ev-101",
                "agent_id": "agt-1",
                "hostname": "srv-01",
                "platform": "windows",
                "source_type": "wineventlog",
                "source_name": "System",
                "event_timestamp": "2026-10-21T12:00:05Z",
                "observed_timestamp": "2026-10-21T12:00:06Z",
                "message": "Network interface connected at 1Gbps",
                "severity": "INFO",
                "source_event_id": "104",
                "source_record_id": 502,
                "metadata": {"provider": "Netwtw10"}
            }
        ]

        # 1. Commit initial batch
        accepted, duplicates = storage.commit_batch("b-1", "agt-1", events_batch)
        assert accepted == ["ev-100", "ev-101"]
        assert duplicates == []
        assert storage.get_event_count() == 2

        # Verify query
        stored = storage.query_events(agent_id="agt-1")
        assert len(stored) == 2
        assert stored[0]["event_id"] in ["ev-100", "ev-101"]

        # Verify replication to central NIGHTWATCH db
        conn2 = sqlite3.connect(nw_db_path)
        try:
            cur = conn2.execute("SELECT COUNT(*) FROM events;")
            assert cur.fetchone()[0] == 2
        finally:
            conn2.close()

        # 2. Resend the same batch (retry scenario)
        accepted2, duplicates2 = storage.commit_batch("b-1-retry", "agt-1", events_batch)
        assert accepted2 == []
        assert set(duplicates2) == {"ev-100", "ev-101"}
        # Total event count must not increase
        assert storage.get_event_count() == 2
