"""
NIGHTWATCH — SPL Search Language and Pipeline Commands Unit Tests
Tests all 18+ supported SPL commands: search, where, fields, table, stats, top, rare,
sort, head, tail, dedup, eval, rex, spath, timechart, bin, rename, fillnull,
eventstats, streamstats, transaction.
"""

import time
import pytest
from app.models.event import NormalizedEvent
from app.search.engine import SearchEngine
from app.storage.engine import StorageEngine


@pytest.fixture
def test_engine(tmp_path):
    db_file = tmp_path / "test_search.db"
    storage = StorageEngine(str(db_file))
    engine = SearchEngine()
    engine.storage = storage

    now = time.time()
    events = [
        NormalizedEvent.create(
            raw='sshd[1]: Failed password for root from 192.168.1.100 port 22 bytes=100',
            host="web-01",
            sourcetype="linux_auth",
            severity="high",
            fields={"user": "root", "src_ip": "192.168.1.100", "bytes": 100, "status": 401}
        ),
        NormalizedEvent.create(
            raw='sshd[2]: Failed password for admin from 192.168.1.100 port 22 bytes=200',
            host="web-01",
            sourcetype="linux_auth",
            severity="high",
            fields={"user": "admin", "src_ip": "192.168.1.100", "bytes": 200, "status": 401}
        ),
        NormalizedEvent.create(
            raw='sshd[3]: Accepted password for alice from 192.168.1.50 port 22 bytes=300',
            host="web-02",
            sourcetype="linux_auth",
            severity="info",
            fields={"user": "alice", "src_ip": "192.168.1.50", "bytes": 300, "status": 200}
        ),
        NormalizedEvent.create(
            raw='sshd[4]: Accepted password for bob from 10.0.0.5 port 22 bytes=400',
            host="web-02",
            sourcetype="linux_auth",
            severity="info",
            fields={"user": "bob", "src_ip": "10.0.0.5", "bytes": 400, "status": 200}
        ),
        NormalizedEvent.create(
            raw='suricata: {"alert": {"signature": "ET SCAN Nmap", "severity": 2}}',
            host="ids-01",
            sourcetype="suricata_eve",
            severity="medium",
            fields={"signature": "ET SCAN Nmap", "bytes": 50, "status": 0}
        )
    ]
    storage.insert_events_batch(events)
    return engine


def test_basic_search_and_filter(test_engine):
    # FTS Term Search
    res = test_engine.execute('"Failed password"')
    assert res.status == "success"
    assert res.result_count == 2

    # Column / Field Filter
    res2 = test_engine.execute('host=web-02')
    assert res2.result_count == 2

    # Severity Filter
    res3 = test_engine.execute('severity=high')
    assert res3.result_count == 2


def test_where_command(test_engine):
    res = test_engine.execute('index=main | where status >= 400')
    assert res.status == "success"
    assert res.result_count == 2


def test_fields_and_table_commands(test_engine):
    res = test_engine.execute('index=main | table user, host, severity')
    assert res.status == "success"
    assert res.columns == ["user", "host", "severity"]
    assert "user" in res.records[0]
    assert "_raw" not in res.records[0]

    # Fields exclusion
    res2 = test_engine.execute('index=main | fields - _raw, raw')
    assert "_raw" not in res2.records[0]


def test_stats_command(test_engine):
    # Count by host
    res = test_engine.execute('index=main | stats count by host')
    assert res.status == "success"
    assert res.result_count == 3  # web-01, web-02, ids-01
    hosts = {r["host"]: r["count"] for r in res.records}
    assert hosts["web-01"] == 2
    assert hosts["web-02"] == 2
    assert hosts["ids-01"] == 1

    # Sum and Avg
    res2 = test_engine.execute('index=main | stats sum(bytes) as total_bytes, avg(bytes) as avg_bytes')
    assert res2.records[0]["total_bytes"] == 1050
    assert res2.records[0]["avg_bytes"] == 210.0

    # Distinct Count (dc)
    res3 = test_engine.execute('index=main | stats dc(user) as distinct_users')
    assert res3.records[0]["distinct_users"] == 4  # root, admin, alice, bob


def test_top_and_rare_commands(test_engine):
    res = test_engine.execute('index=main | top 2 host')
    assert res.status == "success"
    assert len(res.records) <= 2
    assert res.records[0]["count"] == 2
    assert "percent" in res.records[0]

    res_rare = test_engine.execute('index=main | rare 1 host')
    assert res_rare.status == "success"
    assert res_rare.records[0]["host"] == "ids-01"


def test_sort_head_tail_dedup(test_engine):
    # Sort ascending bytes
    res_sort = test_engine.execute('index=main | sort + bytes')
    assert res_sort.records[0]["bytes"] == 50

    # Head
    res_head = test_engine.execute('index=main | head 2')
    assert len(res_head.records) == 2

    # Tail
    res_tail = test_engine.execute('index=main | tail 2')
    assert len(res_tail.records) == 2

    # Dedup
    res_dedup = test_engine.execute('index=main | dedup host')
    assert len(res_dedup.records) == 3


def test_eval_command(test_engine):
    # Arithmetic & conditional eval
    res = test_engine.execute('index=main | eval kb = bytes / 1024 | eval is_err = if(status >= 400, "yes", "no") | table user, kb, is_err')
    assert res.status == "success"
    assert "kb" in res.records[0]
    assert res.records[0]["is_err"] in ("yes", "no")


def test_rex_and_spath_commands(test_engine):
    # Rex named extraction
    res_rex = test_engine.execute('index=main | rex field=_raw "port (?<extracted_port>\\d+)" | table user, extracted_port')
    assert res_rex.status == "success"
    ports = [r.get("extracted_port") for r in res_rex.records if r.get("extracted_port")]
    assert "22" in ports

    # Spath JSON extraction
    res_spath = test_engine.execute('sourcetype=suricata_eve | spath input=raw path=alert.signature output=my_sig | table my_sig')
    assert res_spath.status == "success"
    assert res_spath.records[0]["my_sig"] == "ET SCAN Nmap"


def test_timechart_and_bin(test_engine):
    res_tc = test_engine.execute('index=main | timechart span=1h count')
    assert res_tc.status == "success"
    assert len(res_tc.records) > 0
    assert "_time" in res_tc.records[0]

    res_bin = test_engine.execute('index=main | bin bytes span=100 as byte_bucket | table bytes, byte_bucket')
    assert res_bin.status == "success"
    assert "byte_bucket" in res_bin.records[0]


def test_advanced_commands(test_engine):
    # Rename & Fillnull
    res_rf = test_engine.execute('index=main | rename user as account_name | fillnull value="N/A" account_name | table account_name')
    assert res_rf.status == "success"
    assert "account_name" in res_rf.records[0]

    # Eventstats
    res_es = test_engine.execute('index=main | eventstats count as total_count | table host, total_count')
    assert res_es.status == "success"
    assert len(res_es.records) == 5
    assert res_es.records[0]["total_count"] == 5

    # Streamstats
    res_ss = test_engine.execute('index=main | streamstats count as running_count | table host, running_count')
    assert res_ss.status == "success"
    assert res_ss.records[-1]["running_count"] == 5

    # Transaction
    res_tx = test_engine.execute('index=main | transaction host maxspan=1h')
    assert res_tx.status == "success"
    assert len(res_tx.records) == 3
    assert "eventcount" in res_tx.records[0]
