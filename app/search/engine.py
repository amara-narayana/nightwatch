"""
NIGHTWATCH — SPL Search Engine
Coordinates query parsing, parameterized SQL pushdown, FTS5 retrieval,
pipeline execution, histogram generation, and performance auditing.
"""

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import get_settings
from app.models.event import QueryResult
from app.search.ast_nodes import SearchFilter, SearchStage
from app.search.parser import SPLParser
from app.search.pipeline import PipelineExecutor
from app.storage.engine import get_storage_engine
from app.storage.saved_searches import get_saved_search_manager

logger = logging.getLogger("nightwatch.search")

INDEXED_COLUMNS = {
    "index": "index_name",
    "index_name": "index_name",
    "sourcetype": "sourcetype",
    "severity": "severity",
    "host": "host",
    "source": "source",
    "category": "category",
    "epoch": "epoch"
}


class SearchEngine:
    def __init__(self):
        self.settings = get_settings()
        self.storage = get_storage_engine()
        self.parser = SPLParser()
        self.pipeline = PipelineExecutor()
        self.history_mgr = get_saved_search_manager()

    def execute(
        self,
        query_str: str,
        earliest_epoch: Optional[float] = None,
        latest_epoch: Optional[float] = None,
        limit: Optional[int] = None
    ) -> QueryResult:
        start_time = time.perf_counter()
        effective_limit = min(limit or self.settings.search.default_limit, self.settings.search.max_limit)

        try:
            # 1. Parse SPL Query
            search_stage, pipeline_commands = self.parser.parse(query_str)

            # 2. Build Parameterized SQL Query from SearchStage
            sql, params = self._build_sql(search_stage, earliest_epoch, latest_epoch, effective_limit)

            # 3. Execute Initial SQL / FTS Retrieval
            raw_rows = []
            with self.storage.get_connection() as conn:
                cur = conn.execute(sql, params)
                raw_rows = cur.fetchall()

            total_scanned = len(raw_rows)

            # 4. Convert rows to flattened record dicts
            records: List[Dict[str, Any]] = []
            for row in raw_rows:
                rec = {
                    "id": row["id"],
                    "_time": row["timestamp"],
                    "timestamp": row["timestamp"],
                    "epoch": row["epoch"],
                    "index": row["index_name"],
                    "host": row["host"],
                    "source": row["source"],
                    "sourcetype": row["sourcetype"],
                    "severity": row["severity"],
                    "category": row["category"],
                    "_raw": row["raw"],
                    "raw": row["raw"]
                }
                # Unpack fields_json
                if row["fields_json"]:
                    try:
                        fields_dict = json.loads(row["fields_json"])
                        for k, v in fields_dict.items():
                            if k not in rec:
                                rec[k] = v
                    except Exception:
                        pass
                records.append(rec)

            # 5. Generate Timeline Histogram (Splunk-style event distribution over time)
            timeline_buckets = self._generate_timeline_buckets(records)

            # 6. Execute Subsequent Pipeline Stages
            final_records = self.pipeline.execute(records, pipeline_commands)

            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

            # Determine column names
            columns = self._extract_columns(final_records, pipeline_commands)

            # 7. Record to Search History
            self.history_mgr.log_search(
                query=query_str,
                duration_ms=duration_ms,
                result_count=len(final_records),
                status="success"
            )

            return QueryResult(
                query=query_str,
                status="success",
                duration_ms=duration_ms,
                total_scanned=total_scanned,
                result_count=len(final_records),
                columns=columns,
                records=final_records,
                timeline_buckets=timeline_buckets
            )

        except Exception as e:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.error(f"Search execution failed for query '{query_str}': {e}", exc_info=True)

            self.history_mgr.log_search(
                query=query_str,
                duration_ms=duration_ms,
                result_count=0,
                status="error"
            )

            return QueryResult(
                query=query_str,
                status="error",
                duration_ms=duration_ms,
                total_scanned=0,
                result_count=0,
                columns=[],
                records=[],
                error=str(e)
            )

    def _build_sql(
        self,
        stage: SearchStage,
        earliest_epoch: Optional[float],
        latest_epoch: Optional[float],
        limit: int
    ) -> Tuple[str, Tuple]:
        where_clauses: List[str] = []
        params: List[Any] = []

        # Time range bounds
        if earliest_epoch is not None:
            where_clauses.append("events.epoch >= ?")
            params.append(earliest_epoch)

        if latest_epoch is not None:
            where_clauses.append("events.epoch <= ?")
            params.append(latest_epoch)

        # Filters on indexed columns and fields
        allowed_ops = {"=": "=", "!=": "!=", ">": ">", "<": "<", ">=": ">=", "<=": "<="}
        for flt in stage.filters:
            op = allowed_ops.get(flt.op, "=")
            col_name = INDEXED_COLUMNS.get(flt.field)
            has_wildcard = "*" in str(flt.value)
            val = str(flt.value).replace("*", "%") if has_wildcard else flt.value

            if col_name:
                sql_op = ("NOT LIKE" if op == "!=" else "LIKE") if has_wildcard else op
                where_clauses.append(f"events.{col_name} {sql_op} ?")
                params.append(val)
            else:
                # Structured field stored inside json_extract(events.fields_json, ?)
                # shortcut: flat JSON path only, upgrade if nested dot notation is supported in SPL filters
                safe_field = re.sub(r"[^a-zA-Z0-9_\.]", "", flt.field)
                if not safe_field:
                    continue
                sql_op = ("NOT LIKE" if op == "!=" else "LIKE") if has_wildcard else op
                where_clauses.append(f"json_extract(events.fields_json, ?) {sql_op} ?")
                params.extend([f"$.{safe_field}", val])

        # Full-Text Search terms matching
        if stage.terms:
            fts_match_query = " ".join(f'"{t}"' for t in stage.terms)
            where_clauses.append("events.id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)")
            params.append(fts_match_query)

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
        sql = f"""
            SELECT id, timestamp, epoch, index_name, host, source, sourcetype,
                   severity, category, raw, fields_json
            FROM events
            {where_sql}
            ORDER BY epoch DESC
            LIMIT ?
        """
        params.append(limit)
        return sql, tuple(params)

    def _generate_timeline_buckets(self, records: List[Dict[str, Any]], num_buckets: int = 25) -> List[Dict[str, Any]]:
        """Generates timeline histogram buckets for the search events volume graph."""
        if not records:
            return []

        epochs = [r["epoch"] for r in records if "epoch" in r]
        if not epochs:
            return []

        min_ep = min(epochs)
        max_ep = max(epochs)

        if min_ep == max_ep:
            return [{
                "time": records[0]["timestamp"],
                "count": len(records),
                "epoch": min_ep
            }]

        span = (max_ep - min_ep) / num_buckets
        buckets = [0] * num_buckets

        for ep in epochs:
            idx = int((ep - min_ep) / span)
            if idx >= num_buckets:
                idx = num_buckets - 1
            buckets[idx] += 1

        result_buckets = []
        for i, count in enumerate(buckets):
            b_epoch = min_ep + (i * span)
            iso_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(b_epoch))
            result_buckets.append({
                "time": iso_str,
                "count": count,
                "epoch": b_epoch
            })

        return result_buckets

    @staticmethod
    def _extract_columns(records: List[Dict[str, Any]], pipeline_commands: Optional[List[Any]] = None) -> List[str]:
        if not records:
            return []

        # If last command was TableCommand, honor its exact column specification
        if pipeline_commands:
            for cmd in reversed(pipeline_commands):
                from app.search.ast_nodes import TableCommand
                if isinstance(cmd, TableCommand) and cmd.fields:
                    return list(cmd.fields)

        # Order preferred standard columns first if present
        priority = ["_time", "timestamp", "host", "sourcetype", "severity", "user", "src_ip", "dest_ip", "action", "count", "percent", "_raw", "raw"]
        cols_seen = set()
        ordered_cols = []

        # Check first record keys
        for p in priority:
            if any(p in r for r in records[:50]):
                ordered_cols.append(p)
                cols_seen.add(p)

        for r in records[:50]:
            for k in r.keys():
                if k not in cols_seen and not k.startswith("__"):
                    ordered_cols.append(k)
                    cols_seen.add(k)

        return ordered_cols


_search_engine_instance: Optional[SearchEngine] = None


def get_search_engine() -> SearchEngine:
    global _search_engine_instance
    if _search_engine_instance is None:
        _search_engine_instance = SearchEngine()
    return _search_engine_instance
