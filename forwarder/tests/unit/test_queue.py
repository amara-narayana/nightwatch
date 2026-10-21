"""
Unit Tests for Durable SQLite Local Queue
"""

import datetime
import tempfile
from pathlib import Path
import pytest

from forwarder.agent.event_schema import ForwarderEvent
from forwarder.agent.queue import DurableQueue, QueueFullError


def make_dummy_event(eid: str, msg: str = "test message") -> ForwarderEvent:
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return ForwarderEvent(
        schema_version="1.0",
        event_id=eid,
        agent_id="test-agent",
        hostname="localhost",
        platform="windows",
        source_type="test",
        source_name="test_source",
        event_timestamp=now_iso,
        observed_timestamp=now_iso,
        message=msg
    )


def test_queue_push_and_lease():
    with tempfile.TemporaryDirectory() as td:
        q_path = str(Path(td) / "queue.db")
        q = DurableQueue(q_path, max_capacity=100)

        ev1 = make_dummy_event("eid-1", "msg 1")
        ev2 = make_dummy_event("eid-2", "msg 2")

        inserted = q.push_batch([ev1, ev2])
        assert inserted == 2
        assert q.get_depth() == 2

        # Duplicate insertion ignored safely
        inserted_dup = q.push_batch([ev1])
        assert inserted_dup == 0
        assert q.get_depth() == 2

        # Lease batch
        batch_id, leased = q.lease_batch(batch_size=10)
        assert batch_id is not None
        assert len(leased) == 2
        assert [e.event_id for e in leased] == ["eid-1", "eid-2"]

        # When leased, pending depth is 0
        assert q.get_depth() == 0


def test_queue_ack_retirement():
    with tempfile.TemporaryDirectory() as td:
        q_path = str(Path(td) / "queue.db")
        q = DurableQueue(q_path, max_capacity=100)

        ev1 = make_dummy_event("eid-1")
        ev2 = make_dummy_event("eid-2")
        q.push_batch([ev1, ev2])

        batch_id, leased = q.lease_batch(batch_size=10)
        assert len(leased) == 2

        # Acknowledge eid-1
        retired = q.retire_acknowledged(["eid-1"])
        assert retired == 1

        # Simulate agent restart: eid-2 should be requeued to pending
        q2 = DurableQueue(q_path, max_capacity=100)
        recovered_batch_id, recovered_events = q2.lease_batch(batch_size=10)
        assert len(recovered_events) == 1
        assert recovered_events[0].event_id == "eid-2"


def test_queue_capacity_limit():
    with tempfile.TemporaryDirectory() as td:
        q_path = str(Path(td) / "queue.db")
        q = DurableQueue(q_path, max_capacity=2)

        ev1 = make_dummy_event("eid-1")
        ev2 = make_dummy_event("eid-2")
        ev3 = make_dummy_event("eid-3")

        q.push_batch([ev1, ev2])
        assert q.get_depth() == 2

        with pytest.raises(QueueFullError):
            q.push_batch([ev3])
