# NIGHTWATCH — Detection Rules Reference
## Security Correlation Rules & Incident Investigation Guide

**Product:** NIGHTWATCH — Lightweight Security Intelligence Platform  
**Target Architecture:** Autonomous Rule-Based Detection Engine  
**Version:** 1.0.0  

---

## 1. Detection Architecture Overview

NIGHTWATCH includes a rule-based detection engine that evaluates sliding time windows across normalized security logs. Each rule defines:
- **Evaluation Criteria:** Thresholds, distinct entities, sequences, or regex patterns.
- **Time Window:** Duration in seconds to inspect (e.g., 300s = 5 minutes).
- **Suppression Window:** Deduplication window to prevent alert flooding (e.g., 900s = 15 minutes).
- **Evidence Linking:** Every generated alert stores exact references to the supporting events (`id`, `timestamp`, `host`, `user`, `_raw`), enabling 1-click investigation in the UI.

Alerts progress through a formal SOC lifecycle:
```
New ──> Acknowledged ──> Investigating ──> Resolved
```

---

## 2. Default Out-of-the-Box Security Rules

### Rule 1: Repeated Failed SSH Logins (Brute Force)
- **Rule ID:** `det_ssh_bruteforce`
- **Severity:** HIGH
- **MITRE ATT&CK:** T1110.001 (Brute Force: Password Guessing)
- **Category:** Credential Access
- **Logic:** $\ge 5$ failed authentications (`action="failure"`) from the same `src_ip` within 300 seconds.
- **Investigation Guidance:** Inspect `src_ip` geolocation and targeted accounts. Verify whether any subsequent connection from that IP succeeded.

---

### Rule 2: Password Spraying Campaign Detected
- **Rule ID:** `det_password_spraying`
- **Severity:** CRITICAL
- **MITRE ATT&CK:** T1110.003 (Brute Force: Password Spraying)
- **Category:** Credential Access
- **Logic:** A single `src_ip` generates failed logins across $\ge 3$ distinct `user` accounts within 600 seconds.
- **Investigation Guidance:** Horizontal spraying indicates an attacker attempting common passwords (e.g., `Spring2026!`) across the organization. Check if any targeted account experienced a successful login shortly after.

---

### Rule 3: Successful Authentication After Multiple Failures
- **Rule ID:** `det_auth_success_after_failure`
- **Severity:** HIGH
- **MITRE ATT&CK:** T1078 (Valid Accounts)
- **Category:** Initial Access
- **Logic:** $\ge 3$ failed logins for an account followed immediately by a successful authentication within 600 seconds.
- **Investigation Guidance:** Indicates a successful brute-force attempt or compromised credential. Immediately check the source IP of the successful login against corporate VPN / known employee IPs.

---

### Rule 4: Repeated Authentication Attempts on Privileged Accounts
- **Rule ID:** `det_privileged_account_attempts`
- **Severity:** HIGH
- **MITRE ATT&CK:** T1078.001 (Default Accounts)
- **Category:** Privilege Escalation
- **Logic:** $\ge 3$ authentication attempts targeting administrative accounts (`root`, `administrator`, `admin`, `postgres`, `system`) within 300 seconds.
- **Investigation Guidance:** Direct root/administrator logins over SSH should normally be disabled by policy. Review SSH server configuration (`PermitRootLogin no`).

---

### Rule 5: High-Severity IDS Threat Alert
- **Rule ID:** `det_suricata_high_ids`
- **Severity:** CRITICAL
- **MITRE ATT&CK:** T1071 (Application Layer Protocol), T1041 (Exfiltration)
- **Category:** Network Intrusion
- **Logic:** Suricata EVE event with `event_type="alert"` and severity `1` (Critical) or `2` (High).
- **Investigation Guidance:** Signals network-level exploit kits, Cobalt Strike beacons, reverse shells, or known malware signatures. Extract source IP and inspect endpoint processes.

---

### Rule 6: Suspicious Process or Command-Line Pattern
- **Rule ID:** `det_suspicious_process_execution`
- **Severity:** HIGH
- **MITRE ATT&CK:** T1059.001 (PowerShell), T1033 (System Owner/User Discovery)
- **Category:** Execution
- **Logic:** Matches regex: `(?i)(powershell.*-enc|mimikatz|certutil.*-urlcache|whoami\b.*\/all|curl.*\|\s*sh|wget.*\|\s*bash|vssadmin.*delete.*shadows)`.
- **Investigation Guidance:** Encoded PowerShell commands and `whoami /all` are standard attacker discovery techniques. Decode the Base64 payload in the SPL search console.

---

### Rule 7: Multi-Host Authentication (Potential Lateral Movement)
- **Rule ID:** `det_multi_host_lateral_movement`
- **Severity:** HIGH
- **MITRE ATT&CK:** T1021 (Remote Services)
- **Category:** Lateral Movement
- **Logic:** A single `src_ip` authenticates to $\ge 4$ distinct target `host` endpoints within 600 seconds.
- **Investigation Guidance:** Pivot to the entity timeline in NIGHTWATCH to reconstruct the full chronological path of the attacker across internal infrastructure.

---

## 3. Alert Response Protocol

1. **Acknowledge:** Change alert status to `acknowledged` to claim the investigation.
2. **Drill Down:** Click on the alert in the NIGHTWATCH UI to view triggering events.
3. **Pivot to Search:** Copy the offending `src_ip` or `user` and run:
   ```spl
   src_ip="<offending_ip>" | sort - timestamp
   ```
4. **Resolution:** Record findings in the resolution notes field and set status to `resolved`.
