# NIGHTWATCH — Reverse-Engineering Specification
## Splunk Behavioral Analysis & Independent Implementation Specification

**Product Title:** NIGHTWATCH — Lightweight Security Intelligence Platform  
**Architecture Classification:** Local-First Embedded SIEM & Log Analytics Platform  
**Target Resource Profile:** 8 GB Host RAM, 40 GB SSD, Intel Core i5, Windows 11 / Linux  
**Methodology:** Lawful Black-Box Analysis & Observable Specification Modeling

---

## 1. Executive Summary & Legal Compliance

NIGHTWATCH is an original, independently architected log analytics and security intelligence platform designed to reproduce the observable user workflows, search query semantics, event processing pipelines, and detection capabilities of enterprise SIEM systems like Splunk Enterprise, without using proprietary code, restricted materials, or cloud dependencies.

All capabilities specified herein are derived strictly from publicly available technical documentation, including:
- Splunk Enterprise Architecture & Indexer Management Guides
- Search Processing Language (SPL) Syntax and Search Tutorials
- Splunk Search Command Reference (commands including `search`, `stats`, `timechart`, `rex`, `eval`, `dedup`, etc.)
- Common Information Model (CIM) normalization taxonomies

NIGHTWATCH implements these capabilities from first principles using an embedded, single-binary / lightweight Python 3.11+ and SQLite/FTS5 architecture optimized for resource-constrained laptops and workstations.

---

## 2. Core Capability Specifications

---

### Capability 1: Data Ingestion and Source Management

#### A. User Problem Solved
Security analysts and systems engineers must ingest heterogeneous machine data from distributed endpoints, network appliances, and host operating systems continuously and reliably without data loss across reboots, file rotations, and network interruptions.

#### B. Observable Behavior (Splunk Reference)
In Splunk, Universal Forwarders and local inputs monitor files (`inputs.conf`), network sockets (UDP/TCP syslog, HEC), and event logs. Splunk tracks read byte offsets in `fishbucket` (a B-Tree index storing CRC32/SHA1 hashes of the first 256 bytes plus current file seek offset). When files rotate (e.g., `syslog.1` or timestamped rotations) or truncate, the pointer handles the rotation smoothly without duplicating existing records or missing new events.

#### C. Expected Inputs & Outputs
- **Inputs:** Log files (ASCII/UTF-8 stream), Windows Event Log exports/channels, Suricata EVE JSON streams, stdin, or HTTP log payloads.
- **Outputs:** Raw byte chunks segmented into distinct event records associated with ingestion metadata (`source`, `sourcetype`, `host`, `index`).

#### D. Dependencies
- Filesystem I/O, file hashing (`hashlib.sha256`), checkpoint storage mechanism.

#### E. Resource Costs
- Memory: $O(1)$ relative to file size (buffered reads with 64KB chunks).
- Storage: Checkpoint record $\approx 256$ bytes per monitored source file.
- CPU: Low ($\approx 1\text{--}5\%$ single core during continuous streaming).

#### F. NIGHTWATCH Implementation
- **Component:** `app/collectors/file_collector.py` and `app/collectors/checkpoint.py`.
- **Mechanism:** Persistent checkpoint registry saved in SQLite / JSON metadata. Tracks `{file_path, inode, device, file_size, last_offset, header_hash, last_modified}`.
- **Rotation Handling:** If `file_size < last_offset`, truncation is detected; offset resets to 0. If file header hash matches a previously tracked file under a rotated name, the checkpoint follows the rotation.
- **Supported Inputs:** Text log files, JSON lines, Linux auth log, Windows Event Log JSON, Suricata EVE JSON, synthetic security logs.

#### G. Test Cases
- Incremental read of newly appended lines.
- Mid-file termination and recovery from exact offset.
- Log truncation recovery (file zeroed).
- Log rotation handling (original file renamed, new file created with identical path).
- Corrupted UTF-8 byte stream resilience.

#### H. Known Limitations
- Does not implement proprietary Splunk S2S (Splunk-to-Splunk) binary protocol. Uses standard file monitoring, JSON ingestion, and REST API.

---

### Capability 2: Event Parsing and Normalization

#### A. User Problem Solved
Raw machine logs come in incompatible formats (syslog RFC 3164/5424, Apache/Nginx combined, Windows XML/EVTX, JSON). Security analysts need a unified schema to correlate events across heterogeneous sources.

#### B. Observable Behavior (Splunk Reference)
Splunk uses `props.conf` and `transforms.conf` rules to define event boundaries (`LINE_BREAKER`), extract timestamps (`TIME_PREFIX`, `TIME_FORMAT`), and map fields according to the Common Information Model (CIM) (e.g., `src_ip`, `dest_ip`, `user`, `action`).

#### C. Expected Inputs & Outputs
- **Inputs:** Raw log event lines/objects (`_raw`).
- **Outputs:** Normalized Event schema:
  - `id`: Unique integer / UUID
  - `timestamp`: UTC ISO-8601 string and epoch float
  - `index`: Target index namespace (e.g., `main`, `security`, `ids`)
  - `source`: File path or originator
  - `sourcetype`: Source format identifier (`linux_auth`, `suricata_eve`, `winevt`, `syslog`, `json`)
  - `host`: Hostname or IP
  - `severity`: Normalized string (`critical`, `high`, `medium`, `low`, `info`)
  - `category`: Classification (`authentication`, `network`, `process`, `system`)
  - `fields`: Extracted key-value dictionary (`user`, `src_ip`, `dest_ip`, `dest_port`, `action`, etc.)
  - `raw`: Original untouched string (`_raw`)

#### D. Dependencies
- Standard regular expressions, date-time parsing (`python-dateutil`, `datetime`).

#### E. Resource Costs
- Memory: Minimal per event ($< 2$ KB in-flight).
- CPU: Bounded regex execution with pre-compiled patterns.

#### F. NIGHTWATCH Implementation
- **Component:** `app/parsers/` (`base.py`, `linux_auth.py`, `suricata.py`, `windows_evt.py`, `syslog.py`, `generic_json.py`, `auto.py`).
- **Normalizer:** `app/normalization/cim.py` maps vendor fields to standardized keys (`src_ip`, `dest_ip`, `src_port`, `dest_port`, `user`, `process`, `action`).
- **Resilience:** Malformed events are never discarded; they are ingested with `sourcetype=generic` and `severity=info` with `_raw` intact.

#### G. Test Cases
- Parsing sshd "Accepted password" and "Failed password" lines.
- Parsing sudo command executions.
- Parsing Suricata EVE JSON alerts, DNS queries, and flow logs.
- Parsing Windows Event 4624 (Logon) and 4625 (Failed Logon).
- Timestamp extraction across varied formats (ISO-8601, RFC-2822, Syslog BSD `MMM dd HH:mm:ss`).

#### H. Known Limitations
- Focuses on the most common cybersecurity formats; arbitrary unknown proprietary formats fall back to generic regex / JSON extraction.

---

### Capability 3: Indexing and Retrieval

#### A. User Problem Solved
Analyzing millions of log events requires fast arbitrary keyword searches, boolean filters, time range limits, and field queries without full table scans.

#### B. Observable Behavior (Splunk Reference)
Splunk indexes data into buckets (Hot, Warm, Cold, Frozen) containing raw data sliced into `.tsidx` (time-series index) inverted files, Lexicons, and Bloom filters for high-speed term search.

#### C. Expected Inputs & Outputs
- **Inputs:** Batched normalized events.
- **Outputs:** Persistent on-disk storage with sub-second full-text and structured retrieval over time slices.

#### D. Dependencies
- SQLite with FTS5 (Full-Text Search 5) extension.

#### E. Resource Costs
- Memory: Bounded SQLite buffer cache (configured to 32 MB to 64 MB).
- Disk: Compact database file ($\approx 1.2\times$ raw log size including inverted FTS index).
- Write Latency: Batched inserts yielding $> 5,000$ events/sec on modern SSDs.

#### F. NIGHTWATCH Implementation
- **Component:** `app/storage/engine.py` and `app/storage/models.py`.
- **Database Architecture:**
  - `events` table: Structured fields (`id`, `timestamp`, `epoch`, `index_name`, `host`, `source`, `sourcetype`, `severity`, `category`, `raw`, `fields_json`).
  - `events_fts` table: FTS5 virtual table indexing `raw` text using unicode61 tokenizer.
  - Optimized indexes on `epoch`, `index_name`, `sourcetype`, `severity`, `host`.
  - SQLite WAL (Write-Ahead Logging) mode and `synchronous=NORMAL` for concurrent reads during writes without locking.

#### G. Test Cases
- Insert batch of 10,000 events with verification of count.
- Full-text keyword match retrieval (`search "failed password"`).
- Filter query over epoch timestamp range.
- Combined FTS + structured column queries.

#### H. Known Limitations
- Unlike distributed multi-node Splunk clusters, NIGHTWATCH uses a single embedded SQLite storage engine optimized for local workloads up to tens of millions of events.

---

### Capability 4: Event Timestamps and Field Extraction

#### A. User Problem Solved
Logs frequently contain dynamic fields (e.g., `key=value`, `user="bob"`, `src=10.0.0.1`) that were not predetermined at ingestion time (Schema-on-Read).

#### B. Observable Behavior (Splunk Reference)
Splunk performs automatic search-time field extractions: JSON extraction, key-value pair discovery (`kv`), regex extraction (`rex`), and structured field parsing (`spath`).

#### C. Expected Inputs & Outputs
- **Inputs:** Event raw text or JSON field.
- **Outputs:** Extracted field dictionary dynamically injected into the search event record.

#### D. Dependencies
- Regular expression engine (`re`), JSON parser (`json`).

#### E. Resource Costs
- Memory: $O(1)$ ephemeral fields during query pipeline.
- CPU: Microseconds per event matching regex.

#### F. NIGHTWATCH Implementation
- **Component:** `app/search/extractors.py`.
- **Capabilities:**
  - Automatic Key-Value parser (`foo=bar` or `foo="bar baz"`).
  - Search-time `rex` command supporting named regex capture groups: `(?<field_name>regex)`.
  - Search-time `spath` command extracting nested JSON fields via dot or bracket paths.

#### G. Test Cases
- Extraction of IP and user from non-standard firewall strings via `rex`.
- Dynamic nested JSON traversal via `spath`.
- Automatic KV-mode parsing on unstructured events.

#### H. Known Limitations
- Complex recursive XML parsing is deferred to specialized extractors; JSON and regex are fully implemented.

---

### Capability 5: Search Syntax and Query Execution

#### A. User Problem Solved
Analysts need a flexible pipeline-based query language that enables expressive search, filtering, and transformation without writing raw database queries.

#### B. Observable Behavior (Splunk Reference)
In SPL, searches begin with initial criteria (e.g., `index=security "failed"`) followed by sequential piped stages:
`search | command1 | command2 | command3`

#### C. Expected Inputs & Outputs
- **Inputs:** SPL query string (e.g., `index=security sourcetype=linux_auth | where severity="high" | head 50`).
- **Outputs:** Stream of transformed tabular records or events with performance execution metadata (event count, scan time, execution stats).

#### D. Dependencies
- Custom Lexer, AST Parser, Execution Planner, Parameterized SQL generator.

#### E. Resource Costs
- Memory: Bounded execution queue (streaming generator with hard cap of 50,000 maximum in-flight records).
- Timeout: Configurable query timeout (default 30 seconds).

#### F. NIGHTWATCH Implementation
- **Component:** `app/search/parser.py`, `app/search/lexer.py`, `app/search/pipeline.py`.
- **Safety:** Absolutely no Python `eval()` or shell execution. Full AST validation. Parameterized SQL queries for the initial retrieval stage; pure in-memory streaming pipelines for subsequent transform stages.
- **Supported Base Command Syntax:** Initial boolean expressions (`AND`, `OR`, `NOT`), field equality (`user=admin`), field inequality (`status!=200`), comparison operators (`>`, `<`, `>=`, `<=`), wildcard matching (`host=web*`), quoted phrases (`"invalid user"`).

#### G. Test Cases
- Parse simple keyword query.
- Parse compound boolean logic with parentheses: `(user=alice OR user=bob) AND status=failed`.
- Parse multi-stage pipeline: `index=main | where status>=400 | fields timestamp, host, user`.
- Reject malformed syntax with explicit error messages and column indicators.

#### H. Known Limitations
- Implements the essential core of SPL rather than every proprietary Splunk command.

---

### Capability 6: Statistical Aggregation

#### A. User Problem Solved
Security operations require summarizing thousands of events into aggregate metrics (event counts by IP, data transfer sums, distinct usernames).

#### B. Observable Behavior (Splunk Reference)
The `stats`, `top`, and `rare` commands compute aggregations over groups:
`| stats count, dc(user), avg(response_time) by host, sourcetype`

#### C. Expected Inputs & Outputs
- **Inputs:** Pipelined stream of events with group-by field specifications.
- **Outputs:** Summary table with calculated metric columns.

#### D. Dependencies
- Built-in statistical accumulator (`math`, standard libraries).

#### F. NIGHTWATCH Implementation
- **Component:** `app/search/commands/stats.py`, `app/search/commands/top.py`.
- **Functions Supported:**
  - `count`, `count(field)`
  - `sum(field)`
  - `avg(field)` / `mean(field)`
  - `min(field)`, `max(field)`
  - `dc(field)` / `distinct_count(field)`
  - `values(field)` (distinct list)
- **Top / Rare:** Computes frequency counts and percentage distribution (`percent`), sorting descending or ascending.

#### G. Test Cases
- `stats count by source_ip`
- `stats dc(username) by host`
- `stats sum(bytes), avg(duration) by endpoint`
- `top 10 username`
- Multi-field group-by: `stats count by host, severity`

#### H. Known Limitations
- Approximate streaming percentiles use exact sampling up to memory limit.

---

### Capability 7: Search Pipelines

#### A. User Problem Solved
Complex investigations require chained transformations: extracting a field, filtering on that field, aggregating, renaming columns, and sorting.

#### B. Observable Behavior (Splunk Reference)
SPL passes data through sequential pipes `|` where each command modifies the dataset passed to the next stage.

#### C. Expected Inputs & Outputs
- **Commands:** `search`, `where`, `fields`, `table`, `sort`, `head`, `tail`, `dedup`, `eval`, `rex`, `spath`, `rename`, `fillnull`, `eventstats`, `streamstats`, `transaction`.
- **Output:** Cleaned, structured result array.

#### D. Dependencies
- Pure Python stream transformation engine.

#### E. Resource Costs
- Memory: $O(N)$ for sorting/dedup with $N \le 50,000$; streaming $O(1)$ for filter/projection commands.

#### F. NIGHTWATCH Implementation
- **Component:** `app/search/pipeline.py` and command handlers in `app/search/commands/`.
- **Specific Commands:**
  - `where`: Evaluates conditions on fields with arithmetic and comparison (`where count > 5`).
  - `fields`: Inclusions (`fields + a, b`) and exclusions (`fields - raw`).
  - `table`: Selects specific columns and drops all others.
  - `dedup`: Deduplicates records by specified fields (`dedup source_ip`).
  - `eval`: Computes new fields (`eval speed=bytes/time`, string concatenation, `if()` conditional).
  - `rename`: Renames fields (`rename src_ip as "Source IP"`).
  - `fillnull`: Replaces null/empty values with a placeholder (`fillnull value="unknown" user`).
  - `eventstats`: Computes statistics and appends results to individual events without collapsing them.
  - `streamstats`: Computes running window calculations.
  - `transaction`: Correlates consecutive events matching key fields within a time window (`maxspan`).

#### G. Test Cases
- Verify pipeline ordering invariance and proper state passing.
- Pipeline with 5 chained commands: `search ... | rex ... | eval ... | stats ... | sort - count | head 10`.

#### H. Known Limitations
- Transaction command bounded to maximum 10,000 correlated events to safeguard memory.

---

### Capability 8: Time-Series Analysis

#### A. User Problem Solved
Visualizing event volume spikes, attack bursts, and temporal anomaly patterns requires bucketing events into fixed time intervals.

#### B. Observable Behavior (Splunk Reference)
The `timechart` and `bin`/`bucket` commands group events by temporal intervals:
`| timechart span=5m count by severity`
`| bin _time span=1h`

#### C. Expected Inputs & Outputs
- **Inputs:** Events with timestamps, span duration (e.g., `1m`, `5m`, `1h`, `1d`), aggregation function, and optional secondary split-by field.
- **Outputs:** Chronological time buckets with timestamps as the X-axis and metric columns as Y-values.

#### D. Dependencies
- Epoch calculation and rounding logic.

#### E. Resource Costs
- Memory: Proportional to number of time intervals (e.g., 24 hours of 5-minute bins = 288 points $\times$ split series). Negligible RAM footprint ($< 1$ MB).

#### F. NIGHTWATCH Implementation
- **Component:** `app/search/commands/timechart.py` and `app/search/commands/bin.py`.
- **Mechanism:** Aligns timestamps to standard epoch modulo boundaries based on `span` unit (`s`, `m`, `h`, `d`). Groups by bucket timestamp and pivot field, yielding chart-ready JSON structures.

#### G. Test Cases
- `timechart span=5m count`
- `timechart span=1h count by severity`
- `timechart span=1d avg(bytes)`
- Handling empty buckets (zero-filling).

#### H. Known Limitations
- Sub-millisecond binning is not needed for security log analytics and is capped at 1-second resolution.

---

### Capability 9: Dashboards and Visualizations

#### A. User Problem Solved
Security operations center (SOC) analysts and managers need at-a-glance visibility into system health, active incidents, attack trends, and top affected endpoints without repeatedly running manual queries.

#### B. Observable Behavior (Splunk Reference)
Splunk provides XML/Dashboard Studio dashboards featuring time-series charts, single-value KPIs, pie/donut charts, bar charts, and data tables connected directly to scheduled or real-time queries.

#### C. Expected Inputs & Outputs
- **Inputs:** REST API query results.
- **Outputs:** Responsive, dark-themed interactive visualizations (KPI metric cards, event volume bar charts, severity donut breakdowns, top IP tables).

#### D. Dependencies
- Vanilla JS, CSS, Canvas / SVG charting (fully local, no CDN or internet requirement).

#### E. Resource Costs
- Client-side browser rendering, low DOM footprint.

#### F. NIGHTWATCH Implementation
- **Component:** `app/static/index.html`, `app/static/css/nightwatch.css`, `app/static/js/app.js`, `app/static/js/charts.js`.
- **Aesthetic:** Deep slate dark theme (`#0B0F19`), neon blue/indigo accenting, crisp micro-animations, responsive layout.
- **Panels:**
  1. System KPI Cards (Total Events, Ingestion Rate, Open Alerts, Monitored Sources).
  2. Event Timeline Histogram (with interactive click-to-filter time span).
  3. Severity Distribution Chart.
  4. Top Source IPs & Top Targeted Hosts.
  5. Live Alert Ticker.

#### G. Test Cases
- Verify dashboard loading with empty database.
- Verify dashboard updates upon ingestion of new events.
- Test visual responsiveness across viewport widths.

#### H. Known Limitations
- Dashboard layouts are configured via structured JSON/UI rather than arbitrary drag-and-drop XML.

---

### Capability 10: Alerts and Scheduled Searches

#### A. User Problem Solved
Security threats must be surfaced immediately without an analyst manually monitoring the search screen.

#### B. Observable Behavior (Splunk Reference)
Splunk Alert Manager executes scheduled searches at cron/interval intervals. When matching criteria or thresholds are met, an alert is triggered, recorded, and actions (webhook, email, script) are executed.

#### C. Expected Inputs & Outputs
- **Inputs:** Detection rule definition (SPL query or threshold criteria, check interval, severity, suppression window).
- **Outputs:** Alert records containing triggered timestamp, severity, matched event count, evidence event IDs, and lifecycle state.

#### D. Dependencies
- Background scheduler service (`app/services/scheduler.py`).

#### E. Resource Costs
- Memory: Background worker thread with bounded sleep intervals.
- CPU: Bounded query execution every 30 to 60 seconds.

#### F. NIGHTWATCH Implementation
- **Component:** `app/detection/engine.py`, `app/detection/rules.py`, `app/models/alert.py`.
- **Lifecycle Management:** States: `new` $\rightarrow$ `acknowledged` $\rightarrow$ `investigating` $\rightarrow$ `resolved`.
- **Evidence Linking:** Every alert stores explicit IDs of the events that triggered it, enabling 1-click drill-down in the UI.
- **Deduplication:** Suppression window prevents alert floods for repeated triggers within a configurable time window.

#### G. Test Cases
- Trigger alert upon 5 failed logins within 60 seconds.
- Suppress duplicate alert during active suppression window.
- Lifecycle transition from new to resolved with notes.

#### H. Known Limitations
- Out-of-the-box actions focus on local UI notifications and webhook dispatch; external email delivery requires configuring standard SMTP credentials.

---

### Capability 11: Event Correlation and Investigation

#### A. User Problem Solved
Incidents rarely comprise a single isolated event. Analysts must trace an attacker's movement across multiple log sources (e.g., failed SSH login $\rightarrow$ successful login $\rightarrow$ sudo privilege escalation $\rightarrow$ outbound network connection).

#### B. Observable Behavior (Splunk Reference)
Splunk Incident Review and Event Viewer allow pivoting from an event or alert to related events sharing common pivot fields (`src_ip`, `user`, `host`) within temporal proximity.

#### C. Expected Inputs & Outputs
- **Inputs:** Alert ID or pivot field (e.g., `src_ip=192.168.1.105` and time $T \pm 15\text{m}$).
- **Outputs:** Chronological timeline view of all events associated with the entity across all sourcetypes.

#### D. Dependencies
- Multi-index query planner.

#### E. Resource Costs
- Memory: Streaming result set limited to query budget.

#### F. NIGHTWATCH Implementation
- **Component:** `app/services/investigation.py` and Investigation API.
- **Features:**
  - One-click "Investigate Entity": queries all occurrences of an IP, User, or Host across indices.
  - Event Inspector: detailed raw inspection, field breakdown, JSON viewer, copy-to-clipboard, and SPL pivot generator.

#### G. Test Cases
- Given an alert, retrieve all supporting raw events with exact field parity.
- Retrieve full timeline of an IP spanning Linux auth and Suricata alerts.

#### H. Known Limitations
- Graph visualization is rendered as an interactive chronological swimlane rather than an expensive 3D node-link force graph.

---

### Capability 12: Data Retention and Storage Management

#### A. User Problem Solved
Local SSD storage (40 GB constraint) must not be exhausted by log volume. Expired data must be automatically pruned according to retention rules without database corruption.

#### B. Observable Behavior (Splunk Reference)
Splunk rolls buckets from Hot to Warm to Cold to Frozen. Frozen data is deleted or archived to cold storage when disk space exceeds `maxTotalDataSizeMB` or age exceeds `frozenTimePeriodInSecs`.

#### C. Expected Inputs & Outputs
- **Inputs:** Configured retention policies (`max_age_days`, `max_storage_mb`).
- **Outputs:** Automated database vacuuming, deletion of records older than cutoff, disk usage reporting.

#### D. Dependencies
- SQLite database commands (`DELETE WHERE epoch < cutoff`, `VACUUM` / auto-vacuum, `PRAGMA page_count`).

#### E. Resource Costs
- Disk: Enforces hard cap (e.g., 20 GB default limit to leave headroom on 40 GB SSD).
- I/O: Chunked deletions during low-activity intervals.

#### F. NIGHTWATCH Implementation
- **Component:** `app/services/retention.py`.
- **Policies:**
  - Age-based retention: Purge events older than $N$ days (default: 30 days, configurable).
  - Size-based retention: If SQLite database file exceeds configured MB threshold, delete oldest batches until size is within limit.
  - Disk Space Monitor: Warns in UI if host free disk space drops below 5 GB.

#### G. Test Cases
- Ingest events with synthetic timestamps spanning 60 days; trigger retention cleanup; verify only recent 30 days remain.
- Database size calculation accuracy test.

#### H. Known Limitations
- Does not move frozen data to external AWS S3 Glacier or tapes; deletes locally or exports to a designated local archive directory.

---

### Capability 13: Search History and Saved Searches

#### A. User Problem Solved
Analysts frequently reuse complex SPL queries or need an audit trail of previous investigative searches.

#### B. Observable Behavior (Splunk Reference)
Splunk stores search history in `.splunkhistory` and saved searches in `savedsearches.conf` accessible via Search & Reporting UI.

#### C. Expected Inputs & Outputs
- **Inputs:** Search query string, execution timestamp, result count, user label.
- **Outputs:** Persistent list of historical searches and bookmarkable saved search templates.

#### D. Dependencies
- SQLite storage tables (`search_history`, `saved_searches`).

#### E. Resource Costs
- Storage: $< 1$ MB SQLite table.

#### F. NIGHTWATCH Implementation
- **Component:** `app/storage/saved_searches.py` and Search History API.
- **Features:**
  - Auto-logging of every executed search query with runtime duration and result count.
  - "Save Search" button in search UI with custom name, description, and optional schedule tag.
  - "Recent Queries" dropdown in search bar for instant recall.

#### G. Test Cases
- Record query in history; query history endpoint; verify record.
- Create saved search; run saved search; update saved search.

#### H. Known Limitations
- Unlimited search history trimmed to the 1,000 most recent queries to conserve space.

---

### Capability 14: Application Configuration and Access Controls

#### A. User Problem Solved
Security platforms must be configurable, run securely on localhost without exposing unauthenticated remote access, and gracefully handle service startup and shutdown.

#### B. Observable Behavior (Splunk Reference)
Splunk uses `.conf` files (`server.conf`, `web.conf`, `inputs.conf`), role-based access control (Admin, Power, User), and secure API bindings.

#### C. Expected Inputs & Outputs
- **Inputs:** Configuration file (`config/settings.json`), environment variables, CLI flags.
- **Outputs:** Validated system runtime configuration, localhost binding (`127.0.0.1:8000`), secure defaults.

#### D. Dependencies
- Pydantic Settings, JSON/YAML parser, cryptographic hashing for local auth tokens.

#### E. Resource Costs
- Memory: Negligible.

#### F. NIGHTWATCH Implementation
- **Component:** `app/core/config.py`, `app/api/middleware.py`.
- **Security Features:**
  - Bound to `127.0.0.1` by default (prevents unintentional LAN exposure).
  - Input validation on all endpoints with strict Pydantic models.
  - Path traversal protection (monitored paths sanitized and checked).
  - API rate-limiting and query size caps.

#### G. Test Cases
- Verify rejection of path traversal payloads (`../../etc/passwd`).
- Verify localhost binding default.
- Verify graceful shutdown on SIGINT/SIGTERM.

#### H. Known Limitations
- In local single-user mode, authentication can be bypassed on localhost or secured with an API key/token. Multi-tenant LDAP/SAML integration is deferred.

---

## 3. Architecture Summary & Resource Budget Compliance

| Resource | Budget Constraint | NIGHTWATCH Target | Verification Strategy |
| :--- | :--- | :--- | :--- |
| **Host RAM** | 8 GB total | **< 250 MB idle, < 650 MB peak** | `psutil` real-time measurement |
| **SSD Storage** | ~40 GB available | **< 15 GB total footprint** | SQLite size cap & automatic retention |
| **CPU Utilization** | Intel Core i5 | **< 3% idle, < 40% under query** | Threaded asynchronous collectors |
| **Network** | Zero cloud dependence | **100% offline capable** | Embedded UI assets, no external CDNs |

---

*Specification verified against public Splunk Enterprise documentation and standards.*  
*Maintained under NIGHTWATCH Project.*
