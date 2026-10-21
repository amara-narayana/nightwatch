"""
NIGHTWATCH — Security Detection Engine Unit Tests
"""

import time
import pytest
from app.detection.rules import DetectionRuleRegistry, RuleEvaluator
from app.models.alert import DetectionRule


def test_ssh_brute_force_positive():
    rule = DetectionRule(
        id="det_ssh_bruteforce",
        name="Repeated Failed SSH Logins",
        description="SSH brute force test",
        severity="high",
        category="credential_access",
        rule_type="threshold",
        threshold=5,
        group_by="src_ip",
        conditions={"sourcetype": "linux_auth", "action": "failure"}
    )

    # 6 failed events from 198.51.100.45
    events = [
        {
            "id": i,
            "timestamp": "2026-10-21T05:00:00Z",
            "sourcetype": "linux_auth",
            "action": "failure",
            "src_ip": "198.51.100.45",
            "host": "bastion",
            "raw": f"Failed password for user {i}"
        } for i in range(6)
    ]

    alerts = RuleEvaluator.evaluate_rule(rule, events)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "det_ssh_bruteforce"
    assert alerts[0].event_count == 6


def test_ssh_brute_force_negative():
    rule = DetectionRule(
        id="det_ssh_bruteforce",
        name="Repeated Failed SSH Logins",
        description="SSH brute force test",
        severity="high",
        category="credential_access",
        rule_type="threshold",
        threshold=5,
        group_by="src_ip",
        conditions={"sourcetype": "linux_auth", "action": "failure"}
    )

    # Only 3 failed events (below threshold 5)
    events = [
        {
            "id": i,
            "timestamp": "2026-10-21T05:00:00Z",
            "sourcetype": "linux_auth",
            "action": "failure",
            "src_ip": "198.51.100.45",
            "host": "bastion",
            "raw": f"Failed password for user {i}"
        } for i in range(3)
    ]

    alerts = RuleEvaluator.evaluate_rule(rule, events)
    assert len(alerts) == 0


def test_password_spraying_detection():
    rule = DetectionRule(
        id="det_password_spraying",
        name="Password Spraying Campaign",
        description="Spraying test",
        severity="critical",
        rule_type="distinct_threshold",
        threshold=3,
        group_by="src_ip",
        distinct_field="user",
        conditions={"action": "failure"}
    )

    events = [
        {"id": 1, "timestamp": "2026-10-21T05:00:01Z", "action": "failure", "src_ip": "203.0.113.88", "user": "alice", "raw": "f1", "host": "h1"},
        {"id": 2, "timestamp": "2026-10-21T05:00:02Z", "action": "failure", "src_ip": "203.0.113.88", "user": "bob", "raw": "f2", "host": "h1"},
        {"id": 3, "timestamp": "2026-10-21T05:00:03Z", "action": "failure", "src_ip": "203.0.113.88", "user": "charlie", "raw": "f3", "host": "h1"},
    ]

    alerts = RuleEvaluator.evaluate_rule(rule, events)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "det_password_spraying"


def test_sequence_detection_success_after_failure():
    rule = DetectionRule(
        id="det_auth_sequence",
        name="Success After Failures",
        description="Sequence test",
        severity="high",
        rule_type="sequence",
        failure_threshold=3,
        group_by="user"
    )

    now = time.time()
    events = [
        {"id": 1, "timestamp": "2026-10-21T05:00:01Z", "epoch": now + 1, "action": "failure", "user": "target_user", "raw": "f1"},
        {"id": 2, "timestamp": "2026-10-21T05:00:02Z", "epoch": now + 2, "action": "failure", "user": "target_user", "raw": "f2"},
        {"id": 3, "timestamp": "2026-10-21T05:00:03Z", "epoch": now + 3, "action": "failure", "user": "target_user", "raw": "f3"},
        {"id": 4, "timestamp": "2026-10-21T05:00:04Z", "epoch": now + 4, "action": "success", "user": "target_user", "raw": "s1"},
    ]

    alerts = RuleEvaluator.evaluate_rule(rule, events)
    assert len(alerts) == 1
    assert "Success After Failures" in alerts[0].rule_name


def test_suspicious_process_regex():
    rule = DetectionRule(
        id="det_process_regex",
        name="Suspicious Process",
        description="Pattern test",
        severity="high",
        rule_type="regex_pattern",
        regex=r"(?i)(powershell.*-enc|whoami\s+/all)"
    )

    events = [
        {"id": 1, "timestamp": "2026-10-21T05:00:00Z", "host": "PC-1", "user": "admin", "process": "whoami.exe", "command": "whoami /all", "raw": "whoami /all"}
    ]

    alerts = RuleEvaluator.evaluate_rule(rule, events)
    assert len(alerts) == 1
    assert alerts[0].evidence[0]["id"] == 1
