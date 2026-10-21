"""
NIGHTWATCH — Storage Engine Subsystem Unit Tests
"""

import time
import pytest
from app.models.alert import AlertStatus, SecurityAlert
from app.models.event import NormalizedEvent
from app.storage.engine import StorageEngine


@pytest.fixture
def storage(tmp_path):
    db_file = tmp_path / "test_storage.db"
    return StorageEngine(str(db_file))


def test_batch_insertion_and_count(storage):
    events = [
        NormalizedEvent.create(
            raw=f"Test log line {i} failed password for user{i}",
            sourcetype="linux_auth",
            severity="high" if i % 2 == 0 else "info",
            host=f"srv-0{i%3}",
            fields={"user": f"user{i}", "action": "failure" if i % 2 == 0 else "success"}
        ) for i in range(100)
    ]

    inserted = storage.insert_events_batch(events)
    assert inserted == 100
    assert storage.count_events() == 100
    assert storage.count_events("severity = ?", ("high",)) == 50


def test_fts5_virtual_table_matching(storage):
    e1 = NormalizedEvent.create(raw="Accepted password for devops from 192.168.1.100 port 22")
    e2 = NormalizedEvent.create(raw="Failed password for invalid user hacker from 10.0.0.1 port 22")
    storage.insert_events_batch([e1, e2])

    with storage.get_connection() as conn:
        cur = conn.execute("SELECT rowid FROM events_fts WHERE events_fts MATCH '\"invalid user\"';")
        matches = cur.fetchall()
        assert len(matches) == 1


def test_alert_crud_operations(storage):
    alert = SecurityAlert.create(
        rule_id="det_ssh_bruteforce",
        rule_name="Repeated Failed SSH Logins",
        description="Test alert description",
        severity="high",
        event_count=5,
        evidence=[{"id": 1, "raw": "test evidence"}]
    )
    storage.insert_alert(alert)

    loaded = storage.get_alert_by_id(alert.id)
    assert loaded is not None
    assert loaded.rule_name == "Repeated Failed SSH Logins"
    assert loaded.status == AlertStatus.NEW.value
    assert len(loaded.evidence) == 1

    # Update status
    updated = storage.update_alert_status(alert.id, AlertStatus.INVESTIGATING.value, "Analyst assigned")
    assert updated is True

    loaded_updated = storage.get_alert_by_id(alert.id)
    assert loaded_updated.status == AlertStatus.INVESTIGATING.value
    assert loaded_updated.resolution_notes == "Analyst assigned"


def test_retention_pruning(storage):
    now = time.time()
    old_event = NormalizedEvent.create(raw="Old event 40 days ago")
    old_event.epoch = now - (40 * 86400)

    new_event = NormalizedEvent.create(raw="Recent event today")
    new_event.epoch = now

    storage.insert_events_batch([old_event, new_event])
    assert storage.count_events() == 2

    # Prune older than 30 days
    cutoff = now - (30 * 86400)
    pruned = storage.delete_events_older_than(cutoff)
    assert pruned == 1
    assert storage.count_events() == 1
