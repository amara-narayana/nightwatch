# NIGHTWATCH — SPL Query Language Reference
## Complete Search Processing Language Syntax & Command Guide

**Product:** NIGHTWATCH — Lightweight Security Intelligence Platform  
**Target Architecture:** Embedded SQLite/FTS5 Engine, Zero Cloud Dependencies  
**Version:** 1.0.0  

---

## 1. Syntax Overview & Pipeline Architecture

NIGHTWATCH queries follow the UNIX pipe model:
```
[Initial Search Criteria] | command1 | command2 | ... | commandN
```

Data flows left-to-right as a stream of structured dictionaries (`records`). The initial search stage evaluates against SQLite indexed columns (`index_name`, `sourcetype`, `severity`, `host`, `epoch`) and the FTS5 full-text inverted index. Subsequent piped commands transform, filter, aggregate, calculate, or reorder the stream in memory.

---

## 2. Initial Search Stage (FTS & Field Filtering)

### Full-Text Term Matching
```spl
"failed password"
"error" "connection refused"
```
Matches terms anywhere within the `_raw` text using SQLite FTS5 unicode61 tokenizer.

### Field Comparisons
```spl
index=security
sourcetype=linux_auth
severity=high
host=web-prod-01
status>=400
action!=success
```

### Wildcards
```spl
host=web*
user=adm*
```

---

## 3. Pipelined Commands Reference

### 1. `where` — Row Filtering
Filters events using conditional expressions, comparisons, and boolean logic.
```spl
index=security | where severity="high"
index=security | where status >= 400 AND bytes > 1000
index=security | where like(user, "%admin%")
index=security | where isnull(src_ip)
index=security | where isnotnull(signature)
```

---

### 2. `fields` — Column Projection & Exclusion
Selects or drops fields from the result stream.
```spl
index=main | fields timestamp, host, user, src_ip
index=main | fields - _raw, raw
```

---

### 3. `table` — Tabular Projection
Selects and formats specific columns in explicit order.
```spl
index=security | table timestamp, host, user, action, src_ip
```

---

### 4. `stats` — Statistical Aggregation
Computes aggregate metrics grouped by one or multiple fields.
- Functions: `count`, `sum(field)`, `avg(field)`, `min(field)`, `max(field)`, `dc(field)` (distinct count), `values(field)` (unique list).
```spl
index=security | stats count by src_ip
index=security | stats count, dc(user) as unique_users by host
index=security | stats sum(bytes) as total_bytes, avg(bytes) as avg_bytes by sourcetype
```

---

### 5. `top` and `rare` — Frequency Ranking
Finds the most or least frequent values of a field, calculating count and percentage.
```spl
index=security | top 10 username
index=security | top 5 user by host
index=security | rare 5 host
```

---

### 6. `sort` — Ordering
Sorts result records by one or multiple fields in ascending (`+`) or descending (`-`) order.
```spl
index=security | sort - timestamp
index=security | sort + host, - count
```

---

### 7. `head` and `tail` — Stream Limiting
Returns the first or last $N$ events from the stream.
```spl
index=security | head 50
index=security | tail 20
```

---

### 8. `dedup` — Deduplication
Removes duplicate records based on specified fields.
```spl
index=security | dedup src_ip
index=security | dedup user, host
```

---

### 9. `eval` — Field Calculations & Conditionals
Computes new fields using arithmetic, string manipulation, and conditionals.
- Arithmetic: `+`, `-`, `*`, `/`
- String concatenation: `.`
- Conditional: `if(condition, true_val, false_val)`
- Functions: `lower()`, `upper()`, `len()`, `tostring()`, `tonumber()`, `coalesce()`
```spl
index=security | eval mb = bytes / 1048576
index=security | eval is_alert = if(severity == "high" OR severity == "critical", "yes", "no")
index=security | eval endpoint = host . ":" . tostring(port)
```

---

### 10. `rex` — Search-Time Regular Expression Extraction
Extracts dynamic fields from text using named regex capture groups `(?<field_name>regex)`.
```spl
index=security | rex field=_raw "port (?<extracted_port>\d+)"
index=security | rex "user=(?<usr>\w+) from (?<client_ip>\S+)"
```

---

### 11. `spath` — Structured JSON Path Traversal
Extracts nested fields from structured JSON payloads.
```spl
sourcetype=suricata_eve | spath input=raw path=alert.signature output=sig
sourcetype=json | spath input=raw path=data.users.0.email output=first_user
```

---

### 12. `timechart` — Chronological Bucketing
Groups events into fixed time intervals (`span=1m, 5m, 1h, 1d`) and pivots across series.
```spl
index=security | timechart span=5m count
index=security | timechart span=1h count by severity
index=security | timechart span=1d avg(bytes) by host
```

---

### 13. `bin` / `bucket` — Interval Grouping
Rounds time or numbers into discrete buckets.
```spl
index=main | bin _time span=10m as time_bin
index=main | bin bytes span=1024 as kb_bucket
```

---

### 14. `rename` — Field Renaming
Renames one or multiple fields.
```spl
index=security | rename src_ip as "Source IP", dest_ip as "Target IP"
```

---

### 15. `fillnull` — Null Replacement
Replaces null or blank values with a default string.
```spl
index=security | fillnull value="Unknown User" user
index=security | fillnull value="N/A"
```

---

### 16. `eventstats` — In-Line Summary Statistics
Calculates summary statistics across the dataset and injects the results into every individual event row without collapsing the dataset.
```spl
index=security | eventstats count as total_host_events by host | table timestamp, user, host, total_host_events
```

---

### 17. `streamstats` — Running Cumulative Statistics
Computes running cumulative counts, sums, or averages across the event stream.
```spl
index=security | streamstats count as running_count | table timestamp, user, running_count
```

---

### 18. `transaction` — Sessionization & Event Correlation
Correlates events that share common fields and occur within `maxspan` (maximum duration) or `maxpause` (idle gap).
```spl
index=security | transaction src_ip, user maxspan=30m maxpause=5m
```
Generates combined transaction events with `duration`, `eventcount`, and merged `_raw`.

---

## 4. Safety & Sandboxing Guarantees

1. **Zero Eval Execution:** Query expressions are parsed and evaluated via an AST visitor without executing Python `eval()` or OS shell commands.
2. **Parameterized Storage Access:** Initial retrieval criteria map exclusively to parameterized SQL queries.
3. **Execution Timeouts:** Queries enforce a configurable hard timeout (default 30 seconds).
4. **Memory Caps:** Result streams are bounded to a maximum of 50,000 events to prevent host out-of-memory errors on 8 GB systems.
