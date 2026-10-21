"""
NIGHTWATCH — REST API Endpoints Integration Tests
"""

import pytest
from starlette.testclient import TestClient
from app.api.main import app
from app.storage.engine import get_storage_engine


@pytest.fixture
def client():
    # Initialize storage engine
    storage = get_storage_engine()
    with TestClient(app) as c:
        yield c


def test_system_info_and_health(client):
    res_info = client.get("/api/system/info")
    assert res_info.status_code == 200
    data_info = res_info.json()
    assert data_info["name"] == "NIGHTWATCH"
    assert "NIGHTWATCH" in data_info["title"]

    res_health = client.get("/api/system/health")
    assert res_health.status_code == 200
    data_health = res_health.json()
    assert "application" in data_health
    assert "host" in data_health
    assert "database" in data_health


def test_search_and_validation_api(client):
    # Validate query
    res_val = client.post("/api/search/validate", json={"query": 'index=main | stats count by host'})
    assert res_val.status_code == 200
    assert res_val.json()["valid"] is True

    # Search query
    res_search = client.post("/api/search", json={"query": 'index=main | head 5'})
    assert res_search.status_code == 200
    res_data = res_search.json()
    assert res_data["status"] == "success"
    assert "records" in res_data


def test_ingest_raw_events_api(client):
    payload = {
        "events": [
            "Oct 21 06:00:00 test-host sshd[999]: Failed password for test_user from 10.0.0.99 port 22 ssh2",
            "Oct 21 06:00:01 test-host sshd[999]: Accepted password for test_user from 10.0.0.99 port 22 ssh2"
        ],
        "sourcetype": "linux_auth",
        "index": "security"
    }
    res = client.post("/api/inputs/ingest_raw", json=payload)
    assert res.status_code == 200
    assert res.json()["ingested_count"] == 2


def test_alerts_api(client):
    res = client.get("/api/alerts")
    assert res.status_code == 200
    assert isinstance(res.json(), list)

    res_rules = client.get("/api/alerts/rules/list")
    assert res_rules.status_code == 200
    assert len(res_rules.json()) >= 6
