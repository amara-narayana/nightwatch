"""
Unit Tests for Deduplication Engine and Peer Authentication/Authorization
"""

import sqlite3
import pytest

from forwarder.receiver.authentication import AuthenticationError, extract_client_identity
from forwarder.receiver.authorization import AuthorizationError, authorize_agent
from forwarder.receiver.deduplication import DeduplicationEngine


def test_extract_client_identity():
    peer_cert = {
        "subject": ((("commonName", "agent-endpoint-01"),),),
        "subjectAltName": (("DNS", "agent-endpoint-01"), ("IP Address", "10.0.0.5")),
        "serialNumber": "1234567890",
    }
    ident = extract_client_identity(peer_cert)
    assert ident["common_name"] == "agent-endpoint-01"
    assert "agent-endpoint-01" in ident["sans"]
    assert "10.0.0.5" in ident["sans"]


def test_extract_client_identity_missing():
    with pytest.raises(AuthenticationError, match="No client certificate presented"):
        extract_client_identity(None)


def test_authorize_agent_success():
    ident = {
        "common_name": "agent-endpoint-01",
        "sans": ["agent-endpoint-01"]
    }
    # Open allowlist
    authorize_agent("agent-endpoint-01", ident, allowed_agents=[])

    # Explicit allowlist
    authorize_agent("agent-endpoint-01", ident, allowed_agents=["agent-endpoint-01", "agent-endpoint-02"])


def test_authorize_agent_identity_mismatch():
    ident = {
        "common_name": "agent-endpoint-01",
        "sans": ["agent-endpoint-01"]
    }
    # Claiming to be agent-endpoint-99 with cert belonging to agent-endpoint-01
    with pytest.raises(AuthorizationError, match="does not match client certificate identity"):
        authorize_agent("agent-endpoint-99", ident, allowed_agents=[])


def test_authorize_agent_not_in_allowlist():
    ident = {
        "common_name": "agent-endpoint-01",
        "sans": ["agent-endpoint-01"]
    }
    with pytest.raises(AuthorizationError, match="is not permitted by receiver policy"):
        authorize_agent("agent-endpoint-01", ident, allowed_agents=["agent-other"])


def test_deduplication_engine():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE events (event_id TEXT PRIMARY KEY);")
    conn.execute("INSERT INTO events (event_id) VALUES ('existing-1');")
    conn.commit()

    dedup = DeduplicationEngine()
    batch = [
        {"event_id": "existing-1", "msg": "a"},
        {"event_id": "new-2", "msg": "b"},
        {"event_id": "new-3", "msg": "c"},
        {"event_id": "new-2", "msg": "b-dup-in-same-batch"}
    ]

    new_events, duplicates = dedup.partition_batch(batch, conn)
    new_ids = [e["event_id"] for e in new_events]
    assert new_ids == ["new-2", "new-3"]
    assert "existing-1" in duplicates
    assert len(duplicates) == 2  # existing-1 and the intra-batch duplicate of new-2
