"""
NIGHTWATCH — SPL 'timechart' and 'bin' Commands
Generates time-series buckets, trends, and pivot matrices for charts and histograms.
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from app.search.ast_nodes import AggregationSpec
from app.search.commands.stats import StatsAccumulator


def parse_span_to_seconds(span_str: str) -> int:
    s = span_str.strip().lower()
    if not s:
        return 3600
    unit = s[-1]
    if unit in ('s', 'm', 'h', 'd'):
        num = int(s[:-1])
        if unit == 's':
            return num
        elif unit == 'm':
            return num * 60
        elif unit == 'h':
            return num * 3600
        elif unit == 'd':
            return num * 86400
    try:
        return int(s)
    except Exception:
        return 3600


def execute_timechart(
    records: List[Dict[str, Any]],
    span: str,
    agg: AggregationSpec,
    by_field: Optional[str] = None
) -> List[Dict[str, Any]]:
    if not records:
        return []

    span_seconds = parse_span_to_seconds(span)

    # Map bucket_epoch -> (by_val -> StatsAccumulator)
    time_matrix: Dict[int, Dict[str, StatsAccumulator]] = defaultdict(
        lambda: defaultdict(lambda: StatsAccumulator(agg))
    )
    all_by_values = set()

    for r in records:
        epoch = r.get("epoch")
        if epoch is None and "_time" in r:
            try:
                # Fallback parse _time
                dt = datetime.fromisoformat(str(r["_time"]).replace("Z", "+00:00"))
                epoch = dt.timestamp()
            except Exception:
                continue

        if epoch is None:
            continue

        bucket_epoch = int((epoch // span_seconds) * span_seconds)
        by_val = str(r.get(by_field, "NULL")) if by_field else agg.as_name
        all_by_values.add(by_val)

        acc = time_matrix[bucket_epoch][by_val]
        val = r.get(agg.field) if agg.field else None
        acc.update(val)

    # Sort time buckets chronologically
    sorted_epochs = sorted(time_matrix.keys())
    results = []

    for b_epoch in sorted_epochs:
        dt = datetime.fromtimestamp(b_epoch, timezone.utc)
        iso_str = dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        row: Dict[str, Any] = {
            "_time": iso_str,
            "epoch": b_epoch
        }

        # Populate each series column
        for by_val in sorted(all_by_values):
            if by_val in time_matrix[b_epoch]:
                row[by_val] = time_matrix[b_epoch][by_val].finalize()
            else:
                row[by_val] = 0

        results.append(row)

    return results


def execute_bin(
    records: List[Dict[str, Any]],
    field: str,
    span: str,
    as_name: Optional[str] = None
) -> List[Dict[str, Any]]:
    if not records or not field:
        return records

    out_name = as_name or field
    span_val = parse_span_to_seconds(span)

    for r in records:
        val = r.get(field)
        if val is None:
            continue
        try:
            num = float(val)
            b_val = (num // span_val) * span_val
            r[out_name] = int(b_val) if b_val == int(b_val) else b_val
        except (ValueError, TypeError):
            pass

    return records
