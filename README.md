# NIGHTWATCH — Lightweight Security Intelligence Platform

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-33%20passed-brightgreen.svg)]()
[![Hardware](https://img.shields.io/badge/RAM%20footprint-%3C35%20MB%20idle-cyan.svg)]()

> **NIGHTWATCH** is a complete, local-first Security Information and Event Management (SIEM) and log analytics platform. Inspired by the observable workflows, query syntax, and architectural concepts of enterprise SIEMs like Splunk Enterprise, NIGHTWATCH is an original, independent implementation engineered specifically to run smoothly on constrained local workstations (Intel Core i5, 8 GB RAM, and ~40 GB SSD) with **zero cloud dependencies, zero paid APIs, and zero external database servers**.

---

## Key Highlights

- **Embedded Local-First Storage:** Powered by SQLite with FTS5 inverted text index, Write-Ahead Logging (WAL), and bounded 32 MB cache memory.
- **SPL-Inspired Search Engine:** Lexer, recursive-descent parser, AST optimizer, and stream pipeline executor supporting 18+ commands:
  `search`, `where`, `fields`, `table`, `stats`, `top`, `rare`, `sort`, `head`, `tail`, `dedup`, `eval`, `rex`, `spath`, `timechart`, `bin`, `rename`, `fillnull`, `eventstats`, `streamstats`, and `transaction`.
- **Continuous Ingestion Subsystem:** Monitors log files with persistent byte checkpoints, header hash fingerprints, and automatic truncation and rotation detection.
- **Common Information Model (CIM) Normalization:** Native parsers for Linux Auth (`/var/log/auth.log`, `sshd`, `sudo`), Suricata EVE JSON (`alert`, `dns`, `http`, `flow`), Windows Security Event Logs (Events 4624, 4625, 4688, 4720), RFC 3164/5424 Syslog, and generic JSON.
- **Rule-Based Threat Detection:** Evaluates sliding-window correlation rules for SSH brute-force attacks, horizontal password spraying, successful authentication after repeated failures, privileged account targeting, high-severity IDS threats, and suspicious command-line execution patterns.
- **Evidence-Linked Alert Lifecycle:** Full SOC incident management: `New` $\rightarrow$ `Acknowledged` $\rightarrow$ `Investigating` $\rightarrow$ `Resolved`, linking alerts directly to raw triggering events.
- **Dark-Themed SOC Dashboard:** 100% offline-first responsive web console featuring KPI cards, interactive SVG time-series histograms, severity and sourcetype distribution donuts, top hosts/IPs, saved searches, and live system health telemetry.
- **Hardware Budget Compliant:** Idle resident memory under **35 MB**, peak memory under **120 MB**, and ingestion throughput exceeding **5,000 events/second**.

---

## Quickstart Guide

### 1. Requirements
- Python 3.11+
- Windows 11 or Linux
- No external databases (SQLite FTS5 is built-in)

### 2. Installation
Clone the repository and install the lightweight dependencies:
```bash
git clone https://github.com/amara-narayana/nightwatch.git
cd nightwatch
pip install -r requirements.txt
```

### 3. Generate Synthetic Security Datasets
Generate realistic multi-host sample logs (including simulated brute force, password spraying, and Cobalt Strike alerts):
```bash
python scripts/generate_logs.py
```

### 4. Seed Database & Run Initial Detections
Ingest the sample datasets into the persistent local store and trigger the detection engine:
```bash
python scripts/seed_and_detect.py
```

### 5. Launch NIGHTWATCH
Start the NIGHTWATCH server on `http://127.0.0.1:8000`:

**Windows:**
```cmd
run_nightwatch.bat
# or: python main.py
```

**Linux:**
```bash
chmod +x run_nightwatch.sh
./run_nightwatch.sh
# or: python3 main.py
```

Open your browser to: **[http://127.0.0.1:8000](http://127.0.0.1:8000)**

---

## SPL Query Language Examples

NIGHTWATCH queries use a UNIX-style pipe syntax:
```spl
# Full-Text Search with Boolean Terms
index=security "failed password"

# Field Comparisons & Aggregation
sourcetype=linux_auth | stats count by src_ip

# Statistical Summaries with Aliasing
index=* | stats count, dc(user) as unique_users, avg(bytes) as avg_bytes by host

# Top Entities by Frequency
index=security | top 10 username

# Time-Series Trend Bucketing
index=* | timechart span=5m count

# Row Filtering with Conditions
index=security | where status >= 400 AND severity != "low"

# Dynamic Regex Field Extraction
index=security | rex field=_raw "port (?<extracted_port>\d+)" | table user, extracted_port

# Structured JSON Path Traversal
sourcetype=suricata_eve | spath input=raw path=alert.signature output=threat_sig | table threat_sig

# Computed Fields & Arithmetic
index=* | eval mb = bytes / 1048576 | eval is_alert = if(severity == "high", "yes", "no")

# Correlated Sessions & Transactions
index=security | transaction src_ip, user maxspan=30m
```

For complete syntax and command details, refer to [docs/QUERY_LANGUAGE_REFERENCE.md](docs/QUERY_LANGUAGE_REFERENCE.md).

---

## Out-of-the-Box Security Detection Rules

| Rule ID | Name | Severity | MITRE ATT&CK | Description |
| :--- | :--- | :---: | :---: | :--- |
| `det_ssh_bruteforce` | Repeated Failed SSH Logins | **HIGH** | T1110.001 | $\ge 5$ failed authentications from same IP in 5m |
| `det_password_spraying` | Password Spraying Campaign | **CRITICAL** | T1110.003 | Failed logins across $\ge 3$ distinct users from single IP |
| `det_auth_success_after_failure` | Success Following Failures | **HIGH** | T1078 | $\ge 3$ failures followed immediately by successful login |
| `det_privileged_account_attempts` | Privileged Account Targeting | **HIGH** | T1078.001 | Repeated attempts against root, administrator, admin |
| `det_suricata_high_ids` | High-Severity IDS Threat Alert | **CRITICAL** | T1071 / T1041 | Suricata critical network signature (malware C2 / shell) |
| `det_suspicious_process_execution` | Suspicious Process / Command | **HIGH** | T1059.001 | Encoded PowerShell, mimikatz, certutil, whoami recon |
| `det_multi_host_lateral_movement` | Multi-Host Authentication | **HIGH** | T1021 | Same source IP connecting to $\ge 4$ distinct hosts |

For full details on detection configuration, see [docs/DETECTION_RULES.md](docs/DETECTION_RULES.md).

---

## Real Hardware Performance Benchmarks

Measured on host hardware (Intel Core i5, 8 GB RAM, Windows 11):

| Dataset Size | Ingestion Rate | FTS Match (`"Failed password"`) | Filter (`host=web-prod-01`) | Aggregation (`stats by host`) | Timechart (`span=5m`) | Database Size | Resident RAM |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **1,000** | 4,403.0 ev/s | 223.19 ms | 84.09 ms | 18.94 ms | 24.27 ms | 0.84 MB | 36.12 MB |
| **10,000** | 5,897.9 ev/s | 97.35 ms | 131.39 ms | 72.95 ms | 27.66 ms | 8.72 MB | 41.50 MB |
| **50,000** | 2,868.5 ev/s | 390.33 ms | 249.22 ms | 71.11 ms | 33.67 ms | 32.54 MB | 98.40 MB |

- **Idle Memory:** 34.88 MB
- **Peak Operational Memory:** < 100 MB
- Complete benchmark details available in [docs/BENCHMARK_REPORT.md](docs/BENCHMARK_REPORT.md).

---

## Running the Automated Test Suite

NIGHTWATCH includes a comprehensive automated test suite verifying every component:
```bash
pytest -v
```

```
============================= test session starts =============================
tests/test_api.py::test_system_info_and_health PASSED                    [  3%]
tests/test_api.py::test_search_and_validation_api PASSED                 [  6%]
tests/test_api.py::test_ingest_raw_events_api PASSED                     [  9%]
tests/test_api.py::test_alerts_api PASSED                                [ 12%]
tests/test_collectors.py::test_checkpoint_tracking PASSED                [ 15%]
tests/test_collectors.py::test_file_truncation_detection PASSED          [ 18%]
tests/test_collectors.py::test_collector_incremental_processing PASSED   [ 21%]
tests/test_detection.py::test_ssh_brute_force_positive PASSED            [ 24%]
tests/test_detection.py::test_ssh_brute_force_negative PASSED            [ 27%]
tests/test_detection.py::test_password_spraying_detection PASSED         [ 30%]
tests/test_detection.py::test_sequence_detection_success_after_failure PASSED [ 33%]
tests/test_detection.py::test_suspicious_process_regex PASSED            [ 36%]
tests/test_parsers.py::test_linux_auth_failed_ssh PASSED                 [ 39%]
tests/test_parsers.py::test_linux_auth_accepted_ssh PASSED               [ 42%]
tests/test_parsers.py::test_linux_auth_sudo PASSED                       [ 45%]
tests/test_parsers.py::test_suricata_eve_alert PASSED                    [ 48%]
tests/test_parsers.py::test_windows_event_logon_and_process PASSED       [ 51%]
tests/test_parsers.py::test_syslog_parser PASSED                         [ 54%]
tests/test_parsers.py::test_auto_parser_routing PASSED                   [ 57%]
tests/test_search.py::test_basic_search_and_filter PASSED                [ 60%]
tests/test_search.py::test_where_command PASSED                          [ 63%]
tests/test_search.py::test_fields_and_table_commands PASSED              [ 66%]
tests/test_search.py::test_stats_command PASSED                          [ 69%]
tests/test_search.py::test_top_and_rare_commands PASSED                  [ 72%]
tests/test_search.py::test_sort_head_tail_dedup PASSED                   [ 75%]
tests/test_search.py::test_eval_command PASSED                           [ 78%]
tests/test_search.py::test_rex_and_spath_commands PASSED                 [ 81%]
tests/test_search.py::test_timechart_and_bin PASSED                      [ 84%]
tests/test_search.py::test_advanced_commands PASSED                      [ 87%]
tests/test_storage.py::test_batch_insertion_and_count PASSED             [ 90%]
tests/test_storage.py::test_fts5_virtual_table_matching PASSED           [ 93%]
tests/test_storage.py::test_alert_crud_operations PASSED                 [ 96%]
tests/test_storage.py::test_retention_pruning PASSED                     [100%]

============================= 33 passed in 19.87s =============================
```

---

## Project Repository Architecture

```
nightwatch/
├── app/
│   ├── api/                 # FastAPI routes (search, events, alerts, inputs, system)
│   ├── collectors/          # Continuous file monitoring & rotation/truncation sentinel
│   ├── core/                # Configuration management & environment resolution
│   ├── detection/           # Rule-based threat detection engine & MITRE correlations
│   ├── models/              # Normalized event, alert, and query result models
│   ├── normalization/       # Common Information Model (CIM) field standardizers
│   ├── parsers/             # Linux auth, Suricata EVE, Windows EVTX, Syslog, JSON
│   ├── search/              # SPL Lexer, AST Parser, Pipeline, and Command Executors
│   │   └── commands/        # where, fields, table, stats, top, eval, rex, timechart, etc.
│   ├── services/            # Entity investigation, retention, and system telemetry
│   ├── static/              # Vanilla HTML5/CSS3/ES6 and native SVG charting console
│   └── storage/             # SQLite + FTS5 persistent storage engine
├── config/                  # Validated JSON settings, inputs, and detection rules
├── docs/                    # Technical specifications, feature parity matrix, guides
├── samples/                 # Synthetic multi-source security test datasets
├── scripts/                 # Log generator, seeder, and performance benchmark suites
├── tests/                   # Pytest automated test suite (33 tests)
├── main.py                  # Server entry point
├── requirements.txt         # Lightweight dependencies
└── pyproject.toml           # Project metadata and configuration
```

---

## License

NIGHTWATCH is open-source software licensed under the **Apache License, Version 2.0**.
