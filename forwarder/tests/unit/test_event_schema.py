"""
Unit Tests for Forwarder Event Schema
"""

import datetime
import pytest
from pydantic import ValidationError

from forwarder.agent.event_schema import ForwarderEvent, generate_event_id


def test_generate_event_id_stability():
    id1 = generate_event_id("agent-1", "linux_file", "/var/log/auth.log", "1024:1")
    id2 = generate_event_id("agent-1", "linux_file", "/var/log/auth.log", "1024:1")
    assert id1 == id2
    assert len(id1) == 64  # SHA-256 hex string

    id3 = generate_event_id("agent-1", "linux_file", "/var/log/auth.log", "1024:2")
    assert id1 != id3


def test_forwarder_event_valid():
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    eid = generate_event_id("agent-1", "wineventlog", "System", "100")
    event = ForwarderEvent(
        schema_version="1.0",
        event_id=eid,
        agent_id="agent-1",
        hostname="WORKSTATION-01",
        platform="windows",
        source_type="wineventlog",
        source_name="System",
        event_timestamp=now_iso,
        observed_timestamp=now_iso,
        message="Service started successfully",
        severity="INFO",
        source_event_id="7036",
        source_record_id=100,
        metadata={"provider": "Service Control Manager"}
    )
    assert event.event_id == eid
    assert event.message == "Service started successfully"
    dump = event.model_dump()
    assert dump["agent_id"] == "agent-1"


def test_forwarder_event_missing_required():
    with pytest.raises(ValidationError):
        ForwarderEvent(
            schema_version="1.0",
            # Missing event_id, agent_id, etc.
            message="incomplete"
        )


def test_forwarder_event_oversized_message():
    huge_msg = "A" * (65536 + 1)
    with pytest.raises(ValidationError):
        ForwarderEvent(
            schema_version="1.0",
            event_id="a" * 64,
            agent_id="agent-1",
            hostname="host",
            platform="linux",
            source_type="file",
            source_name="/var/log/test.log",
            event_timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            observed_timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            message=huge_msg
        )
