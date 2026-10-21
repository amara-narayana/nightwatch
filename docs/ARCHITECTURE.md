# NIGHTWATCH — Architecture Documentation
## Lightweight Security Intelligence Platform

**Hardware Target:** Intel Core i5, 8 GB RAM, ~40 GB available SSD  
**Operating Environment:** Windows 11 host (or Linux), Python 3.11+  
**Architecture Style:** Single-process / embedded local-first SIEM  
**Design Philosophy:** Zero cloud dependencies, zero paid APIs, bounded resource footprint, deterministic performance.

---

## 1. High-Level System Architecture

```
                                  +---------------------------------------+
                                  |     NIGHTWATCH Web UI (Dark Theme)    |
                                  |   Vanilla HTML5 / CSS3 / ES6 / SVG   |
                                  +-------------------+-------------------+
                                                      |  REST API / SSE
                                                      v
+---------------------------------------------------------------------------------------------------+
|                                     FASTAPI APPLICATION SERVER                                    |
|                                                                                                   |
|  +-----------------+  +------------------+  +-------------------+  +----------------------------+ |
|  | Search API      |  | Alerts API       |  | Events & Inspect  |  | Health & System Retention  | |
|  | /api/search     |  | /api/alerts      |  | /api/events       |  | /api/system                | |
|  +--------+--------+  +--------+---------+  +---------+---------+  +--------------+-------------+ |
+-----------|--------------------|----------------------|---------------------------|---------------+
            |                    |                      |                           |
            v                    v                      v                           v
+--------------------+  +------------------+  +-------------------+        +----------------+
| SPL Query Engine   |  | Detection Engine |  | Investigation     |        | Retention &    |
| - Lexer & Parser   |  | - Rule Registry  |  | - Timeline Pivots |        | Disk Guardian  |
| - AST Optimizer    |  | - Background Sched|  | - Entity Drilldown|        | - Age Pruning  |
| - Stream Pipeline  |  | - Evidence Link  |  |                   |        | - Size Pruning |
+---------+----------+  +--------+---------+  +---------+---------+        +--------+-------+
          |                      |                      |                           |
          +----------------------+----------------------+---------------------------+
                                 |
                                 v
          +-----------------------------------------------+
          |          STORAGE ENGINE (SQLite + FTS5)        |
          |  - WAL mode (Write-Ahead Logging)             |
          |  - Bounded 32 MB cache                        |
          |  - `events` table (Indexed Structured B-Tree) |
          |  - `events_fts` table (FTS5 Unicode61 Index)  |
          |  - `alerts`, `rules`, `checkpoints` tables    |
          +----------------------+------------------------+
                                 ^
                                 | Batched Transactions (e.g. 500 events / batch)
                                 |
          +-----------------------------------------------+
          |             INGESTION SUBSYSTEM               |
          |                                               |
          |  +-----------------------------------------+  |
          |  |  Continuous File Collector Worker       |  |
          |  |  - Persistent Checkpoint Registry       |  |
          |  |  - Rotation & Truncation Sentinel       |  |
          |  +--------------------+--------------------+  |
          |                       |                       |
          |                       v                       |
          |  +-----------------------------------------+  |
          |  |  Parser & CIM Normalizer Engine         |  |
          |  |  (Linux Auth, Syslog, Suricata, WinEVT) |  |
          |  +--------------------+--------------------+  |
          |                       |                       |
          |                       v                       |
          |  +-----------------------------------------+  |
          |  |  Bounded Ingestion Queue (Max 5,000)    |  |
          |  +-----------------------------------------+  |
          +-----------------------------------------------+
                                 ^
                                 | Monitored Local Log Paths
          +-----------------------------------------------+
          |        OPERATING SYSTEM & LOG SOURCES         |
          |  - Linux Auth Log (/var/log/auth.log)         |
          |  - Syslog / Systemd Journal Exports           |
          |  - Suricata EVE JSON (eve.json)               |
          |  - Windows Event Log Exports (JSON / XML)     |
          |  - Application / Custom Security Logs         |
          +-----------------------------------------------+
```

---

## 2. Resource Envelope & Budgets

NIGHTWATCH is engineered specifically to operate comfortably alongside an analyst's other host applications on an 8 GB RAM laptop.

### A. Memory Budget (Target: < 300 MB typical, < 650 MB peak under heavy search)
1. **Python Runtime & FastAPI:** $\approx 45\text{--}65\text{ MB}$ base resident memory.
2. **SQLite In-Memory Buffer Cache:** Hard-configured to $32\text{ MB}$ (`PRAGMA cache_size = -32000`).
3. **Ingestion Queue:** Bounded buffer capped at 5,000 normalized events ($\approx 10\text{ MB}$).
4. **Search Pipeline Buffer:** Maximum query result set in memory capped at 50,000 events ($\approx 40\text{--}80\text{ MB}$). Subsequent pipeline stages use generator streams to discard unprojected fields early (e.g., dropping `_raw` when executing `table` or `stats`).
5. **Detection Rule Context:** Sliding memory window for correlation rules capped at 15 minutes or 10,000 candidate events ($\approx 15\text{ MB}$).
6. **Total Headroom Remaining for Host OS:** $> 7.3\text{ GB}$ available for Windows and user apps.

### B. Storage Budget (Target: < 15 GB on a 40 GB SSD)
1. **Database Compaction:** SQLite with Page Size 4096 bytes and WAL mode.
2. **FTS5 Inverted Index:** Overhead is approximately $20\text{--}30\%$ of the raw text size.
3. **Automated Retention Engine:**
   - Default Retention Period: 30 days (configurable).
   - Maximum Storage Cap: 15,000 MB (15 GB) (configurable).
   - If disk usage hits the threshold, background cleaner prunes the oldest epoch buckets in 5,000-event transactions until within budget.
   - Host Free Space Guard: Triggers high-priority alert if host free disk drops below 5 GB.

### C. CPU Utilization Budget
1. **Idle State:** $< 1.5\%$ CPU. File watcher uses poll sleep intervals ($500\text{ ms}$ to $1\text{ s}$).
2. **Continuous Streaming Ingestion:** $< 8\%$ CPU on single Core i5 thread.
3. **Active Complex Search:** Bounded to 1 query worker thread per request, with timeout kill-switch (default $30\text{ s}$).

---

## 3. Storage Layer Architecture

### Database Schema (SQLite 3.40+)

```sql
-- Main Events Table
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,         -- ISO-8601 UTC string (e.g., '2026-10-21T05:30:00.123456Z')
    epoch REAL NOT NULL,             -- Unix Epoch in seconds with millisecond float
    index_name TEXT NOT NULL,        -- Index namespace (e.g., 'main', 'security')
    host TEXT NOT NULL,              -- Originating hostname / IP
    source TEXT NOT NULL,            -- Source file path or socket identifier
    sourcetype TEXT NOT NULL,        -- Format parser identifier ('linux_auth', 'suricata_eve', etc.)
    severity TEXT NOT NULL,          -- Normalized severity ('critical', 'high', 'medium', 'low', 'info')
    category TEXT NOT NULL,          -- Normalized classification ('authentication', 'network', 'process', etc.)
    raw TEXT NOT NULL,               -- Untouched raw log string (_raw)
    fields_json TEXT NOT NULL        -- JSON string of extracted structured key-value pairs
);

-- Fast Indexing for Range Queries & Filtering
CREATE INDEX IF NOT EXISTS idx_events_epoch ON events(epoch);
CREATE INDEX IF NOT EXISTS idx_events_index ON events(index_name);
CREATE INDEX IF NOT EXISTS idx_events_sourcetype ON events(sourcetype);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);
CREATE INDEX IF NOT EXISTS idx_events_composite ON events(index_name, epoch DESC);

-- Full-Text Search (FTS5) Virtual Table for Sub-Second Term Matching
CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
    raw,
    content='events',
    content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
);

-- Automatic FTS5 Maintenance Triggers
CREATE TRIGGER IF NOT EXISTS events_ai AFTER INSERT ON events BEGIN
  INSERT INTO events_fts(rowid, raw) VALUES (new.id, new.raw);
END;

CREATE TRIGGER IF NOT EXISTS events_ad AFTER DELETE ON events BEGIN
  INSERT INTO events_fts(events_fts, rowid, raw) VALUES('delete', old.id, old.raw);
END;

-- Ingestion Checkpoints Table
CREATE TABLE IF NOT EXISTS checkpoints (
    source_path TEXT PRIMARY KEY,
    inode INTEGER,
    device INTEGER,
    last_offset INTEGER NOT NULL,
    file_size INTEGER NOT NULL,
    header_hash TEXT NOT NULL,
    last_modified REAL NOT NULL,
    updated_at REAL NOT NULL
);

-- Security Alerts Table
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,             -- UUID
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,          -- 'critical', 'high', 'medium', 'low'
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    triggered_at TEXT NOT NULL,
    triggered_epoch REAL NOT NULL,
    status TEXT NOT NULL,            -- 'new', 'acknowledged', 'investigating', 'resolved'
    event_count INTEGER NOT NULL,
    evidence_json TEXT NOT NULL,     -- JSON array of triggering event IDs and summaries
    resolution_notes TEXT,
    updated_at REAL NOT NULL
);

-- Saved Searches Table
CREATE TABLE IF NOT EXISTS saved_searches (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    query TEXT NOT NULL,
    description TEXT,
    created_at REAL NOT NULL,
    last_run_at REAL,
    run_count INTEGER DEFAULT 0
);

-- Search History Table
CREATE TABLE IF NOT EXISTS search_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    query TEXT NOT NULL,
    executed_at REAL NOT NULL,
    duration_ms REAL NOT NULL,
    result_count INTEGER NOT NULL,
    status TEXT NOT NULL
);
```

---

## 4. Ingestion Pipeline & Checkpoint Sentinel

### Ingestion Flow:
1. **Collector Loop:** Reads monitored file paths defined in `config/inputs.json`.
2. **Fingerprint Verification:**
   - Reads first 512 bytes to compute SHA-256 header hash.
   - Compares with stored checkpoint:
     - If `file_size < checkpoint.last_offset`: Truncation detected $\rightarrow$ seeks to 0.
     - If inode/hash matches but path changed: Rotation detected $\rightarrow$ finishes old file, tracks new file.
3. **Chunked Stream Parser:** Reads new lines up to file end, updates `last_offset`.
4. **Parser Resolution:** Identifies parser by `sourcetype` configuration or signature match (e.g., valid JSON with `"event_type"` $\rightarrow$ Suricata; `sshd[...]` $\rightarrow$ Linux Auth).
5. **CIM Normalization:** Maps native fields to standardized taxonomy (`src_ip`, `dest_ip`, `user`, etc.).
6. **Batched Transaction:** Accumulates up to 500 records or 500 ms elapsed, then commits a single atomic SQLite transaction with FTS index update.

---

## 5. SPL Search Execution Architecture

SPL queries are executed through an optimized 4-stage pipeline:

```
[ Raw Query String: 'index=security "failed password" | stats count by user | sort - count' ]
                                     |
                                     v
                        [ 1. Lexer & Tokenizer ]
      Identifies keywords, string literals, operators, pipe symbols '|'
                                     |
                                     v
                        [ 2. AST Parser & Planner ]
   Breaks query into:
   - Initial Retrieval Stage (SearchSpec)
   - Pipeline Stages: [StatsCommand(count, by=[user]), SortCommand(-count)]
                                     |
                                     v
                    [ 3. SQL Pushdown Optimization ]
   Transforms initial criteria into indexed parameterized SQL:
   SELECT id, timestamp, epoch, index_name, host, source, sourcetype,
          severity, category, raw, fields_json
   FROM events
   WHERE index_name = 'security'
     AND id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH '"failed password"')
   ORDER BY epoch DESC LIMIT 50000;
                                     |
                                     v
                 [ 4. Streaming In-Memory Pipeline Execution ]
   Streams matching records through chained command transformers:
   SQL Stream -> [stats accumulator] -> [sort] -> Final Table / Records
```

---

## 6. Security & Localhost Binding Model

1. **Localhost Binding:** Server listens exclusively on `127.0.0.1:8000` by default. Remote exposure requires an explicit `--host 0.0.0.0` flag and token configuration.
2. **Safe Query Execution:** The SPL parser is a strict recursive-descent parser. Queries cannot execute Python code, call OS commands, or execute arbitrary unescaped SQL.
3. **Path Traversal Shield:** File collector enforces path checks, rejecting directory traversal sequences or attempts to read root device handles outside configured paths.
4. **HTML Escaping:** Web UI renders raw log strings safely inside `<pre><code>` blocks with explicit character escaping to prevent stored XSS attacks via malicious log lines.

---

*Architectural specification validated for production implementation.*
