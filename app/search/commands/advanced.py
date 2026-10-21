"""
NIGHTWATCH — Advanced SPL Commands: rename, fillnull, eventstats, streamstats, transaction
"""

from collections import defaultdict
from typing import Any, Dict, List, Optional
from app.search.ast_nodes import AggregationSpec
from app.search.commands.stats import StatsAccumulator


def execute_rename(records: List[Dict[str, Any]], mappings: Dict[str, str]) -> List[Dict[str, Any]]:
    if not mappings:
        return records

    for r in records:
        for old_k, new_k in mappings.items():
            if old_k in r:
                r[new_k] = r.pop(old_k)
    return records


def execute_fillnull(records: List[Dict[str, Any]], value: Any = "NULL", fields: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    target_fields = set(fields) if fields else None

    for r in records:
        if target_fields:
            for f in target_fields:
                if f not in r or r[f] is None or r[f] == "":
                    r[f] = value
        else:
            for k in list(r.keys()):
                if r[k] is None or r[k] == "":
                    r[k] = value
    return records


def execute_eventstats(
    records: List[Dict[str, Any]],
    aggregations: List[AggregationSpec],
    group_by: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    if not records:
        return []

    group_fields = group_by or []
    groups: Dict[tuple, List[StatsAccumulator]] = defaultdict(
        lambda: [StatsAccumulator(agg) for agg in aggregations]
    )

    # 1. First pass: compute aggregates
    for r in records:
        key = tuple(r.get(f, "NULL") for f in group_fields) if group_fields else ()
        accumulators = groups[key]
        for acc in accumulators:
            val = r.get(acc.field) if acc.field else None
            acc.update(val)

    # 2. Finalize computed aggregates for each group
    computed_cache = {}
    for key, accumulators in groups.items():
        computed_cache[key] = {acc.as_name: acc.finalize() for acc in accumulators}

    # 3. Second pass: enrich original records without collapsing
    for r in records:
        key = tuple(r.get(f, "NULL") for f in group_fields) if group_fields else ()
        group_stats = computed_cache[key]
        r.update(group_stats)

    return records


def execute_streamstats(
    records: List[Dict[str, Any]],
    aggregations: List[AggregationSpec],
    window: Optional[int] = None
) -> List[Dict[str, Any]]:
    """Computes running cumulative statistics across the event stream."""
    accumulators = [StatsAccumulator(agg) for agg in aggregations]

    for r in records:
        for acc in accumulators:
            val = r.get(acc.field) if acc.field else None
            acc.update(val)
            r[acc.as_name] = acc.finalize()

    return records


def execute_transaction(
    records: List[Dict[str, Any]],
    fields: List[str],
    maxspan_seconds: Optional[int] = None,
    maxpause_seconds: Optional[int] = None
) -> List[Dict[str, Any]]:
    """Groups events sharing common field values into cohesive transaction events."""
    if not records or not fields:
        return records

    # Sort records chronologically
    sorted_recs = sorted(records, key=lambda x: x.get("epoch", 0.0))

    transactions: List[Dict[str, Any]] = []
    # Key -> Current active transaction dict
    active_tx: Dict[tuple, Dict[str, Any]] = {}

    for r in sorted_recs:
        key = tuple(r.get(f) for f in fields)
        epoch = r.get("epoch", 0.0)

        tx = active_tx.get(key)
        should_close = False

        if tx is not None:
            # Check maxspan constraint
            if maxspan_seconds and (epoch - tx["start_epoch"]) > maxspan_seconds:
                should_close = True
            # Check maxpause constraint
            if maxpause_seconds and (epoch - tx["last_epoch"]) > maxpause_seconds:
                should_close = True

        if should_close or tx is None:
            if tx is not None:
                transactions.append(tx)
            # Start new transaction
            tx = {
                "_time": r.get("_time") or r.get("timestamp"),
                "start_epoch": epoch,
                "last_epoch": epoch,
                "duration": 0.0,
                "eventcount": 1,
                "_raw": r.get("_raw", ""),
            }
            # Copy grouping fields
            for f in fields:
                tx[f] = r.get(f)
            active_tx[key] = tx
        else:
            # Append to active transaction
            tx["last_epoch"] = epoch
            tx["duration"] = round(epoch - tx["start_epoch"], 3)
            tx["eventcount"] += 1
            tx["_raw"] += "\n" + r.get("_raw", "")

    # Close remaining transactions
    for tx in active_tx.values():
        transactions.append(tx)

    # Sort final transactions descending
    transactions.sort(key=lambda x: x.get("start_epoch", 0.0), reverse=True)
    return transactions
