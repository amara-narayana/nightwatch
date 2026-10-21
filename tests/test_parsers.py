"""
NIGHTWATCH — Parser Subsystem Unit Tests
"""

import json
import pytest
from app.parsers.linux_auth import LinuxAuthParser
from app.parsers.suricata import SuricataEveParser
from app.parsers.windows_evt import WindowsEventParser
from app.parsers.syslog import SyslogParser
from app.parsers.generic_json import GenericJsonParser
from app.parsers.auto import AutoParser


def test_linux_auth_failed_ssh():
    parser = LinuxAuthParser()
    raw = "Oct 21 05:14:20 bastion-01 sshd[4096]: Failed password for invalid user admin from 198.51.100.45 port 42100 ssh2"
    ev = parser.parse(raw, source="samples/auth.log")
    assert ev is not None
    assert ev.host == "bastion-01"
    assert ev.sourcetype == "linux_auth"
    assert ev.severity in ("high", "medium")
    assert ev.fields["action"] == "failure"
    assert ev.fields["user"] == "admin"
    assert ev.fields["src_ip"] == "198.51.100.45"
    assert ev.fields["src_port"] == 42100


def test_linux_auth_accepted_ssh():
    parser = LinuxAuthParser()
    raw = "Oct 21 05:15:00 web-prod-01 sshd[1024]: Accepted publickey for devops from 192.168.1.50 port 55120 ssh2"
    ev = parser.parse(raw, source="samples/auth.log")
    assert ev is not None
    assert ev.host == "web-prod-01"
    assert ev.fields["action"] == "success"
    assert ev.fields["user"] == "devops"
    assert ev.fields["src_ip"] == "192.168.1.50"


def test_linux_auth_sudo():
    parser = LinuxAuthParser()
    raw = "Oct 21 05:16:30 db-prod-01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/systemctl restart postgres"
    ev = parser.parse(raw, source="samples/auth.log")
    assert ev is not None
    assert ev.fields["user"] == "deploy"
    assert ev.fields["target_user"] == "root"
    assert "/bin/systemctl" in ev.fields["command"]


def test_suricata_eve_alert():
    parser = SuricataEveParser()
    raw = json.dumps({
        "timestamp": "2026-10-21T05:20:00.123456+0000",
        "event_type": "alert",
        "src_ip": "192.168.1.105",
        "src_port": 49812,
        "dest_ip": "198.51.100.99",
        "dest_port": 8443,
        "proto": "TCP",
        "alert": {
            "signature": "ET MALWARE Cobalt Strike Beacon Observed",
            "severity": 1,
            "category": "A Network Trojan was detected",
            "action": "allowed"
        }
    })
    ev = parser.parse(raw, source="eve.json")
    assert ev is not None
    assert ev.index_name == "ids"
    assert ev.severity == "critical"
    assert ev.fields["src_ip"] == "192.168.1.105"
    assert ev.fields["dest_ip"] == "198.51.100.99"
    assert "Cobalt Strike" in ev.fields["signature"]


def test_windows_event_logon_and_process():
    parser = WindowsEventParser()
    raw_4624 = json.dumps({
        "EventID": 4624,
        "TimeCreated": "2026-10-21T05:30:00.000Z",
        "Computer": "PC-01.corp",
        "EventData": {
            "TargetUserName": "alice",
            "IpAddress": "192.168.1.99",
            "IpPort": 51234
        }
    })
    ev1 = parser.parse(raw_4624)
    assert ev1 is not None
    assert ev1.fields["action"] == "success"
    assert ev1.fields["user"] == "alice"
    assert ev1.fields["src_ip"] == "192.168.1.99"

    raw_4688 = json.dumps({
        "EventID": 4688,
        "TimeCreated": "2026-10-21T05:31:00.000Z",
        "Computer": "PC-01.corp",
        "EventData": {
            "SubjectUserName": "alice",
            "NewProcessName": "C:\\Windows\\System32\\whoami.exe",
            "CommandLine": "whoami.exe /all"
        }
    })
    ev2 = parser.parse(raw_4688)
    assert ev2 is not None
    assert ev2.category == "process"
    assert "whoami.exe" in ev2.fields["command"]


def test_syslog_parser():
    parser = SyslogParser()
    raw = "<30>Oct 21 05:40:00 srv-01 kernel: [12345.67] Out of memory: Kill process 890 (oom_test)"
    ev = parser.parse(raw)
    assert ev is not None
    assert ev.host == "srv-01"
    assert ev.fields["process"] == "kernel"
    assert "Out of memory" in ev.fields["message"]


def test_auto_parser_routing():
    auto = AutoParser()
    # Route JSON to Suricata
    s_raw = json.dumps({"event_type": "alert", "alert": {"signature": "Test", "severity": 2}})
    ev_s = auto.parse(s_raw)
    assert ev_s.sourcetype == "suricata_eve"

    # Route SSH to Linux Auth
    a_raw = "Oct 21 05:50:00 host-1 sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2"
    ev_a = auto.parse(a_raw)
    assert ev_a.sourcetype == "linux_auth"
