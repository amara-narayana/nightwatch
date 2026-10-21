"""
NIGHTWATCH — SPL 'stats' Command
Computes aggregations (count, sum, avg, min, max, dc, values) grouped by specified fields.
"""

from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple
from app.search.ast_nodes import AggregationSpec


class StatsAccumulator:
    def __init__(self, spec: AggregationSpec):
        self.spec = spec
        self.func = spec.func
        self.field = spec.field
        self.as_name = spec.as_name

        self.count = 0
        self.sum = 0.0
        self.min = None
        self.max = None
        self.distinct_set = set()

    def update(self, val: Any) -> None:
        if self.func == "count":
            if self.field is None or val is not None:
                self.count += 1
            return

        if val is None:
            return

        # Numeric conversions for sum, avg, min, max
        if self.func in ("sum", "avg", "mean", "min", "max"):
            try:
                num = float(val)
                self.count += 1
                self.sum += num
                if self.min is None or num < self.min:
                    self.min = num
                if self.max is None or num > self.max:
                    self.max = num
            except (ValueError, TypeError):
                pass

        elif self.func in ("dc", "distinct_count", "values"):
            self.distinct_set.add(val)

    def finalize(self) -> Any:
        if self.func == "count":
            return self.count
        elif self.func == "sum":
            return round(self.sum, 4) if self.sum != int(self.sum) else int(self.sum)
        elif self.func in ("avg", "mean"):
            if self.count == 0:
                return 0.0
            return round(self.sum / self.count, 4)
        elif self.func == "min":
            return self.min
        elif self.func == "max":
            return self.max
        elif self.func in ("dc", "distinct_count"):
            return len(self.distinct_set)
        elif self.func == "values":
            return sorted(list(self.distinct_set), key=lambda x: str(x))
        return self.count


def execute_stats(
    records: List[Dict[str, Any]],
    aggregations: List[AggregationSpec],
    group_by: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    group_fields = group_by or []

    # Map group_key -> list of accumulators
    groups: Dict[Tuple, List[StatsAccumulator]] = defaultdict(
        lambda: [StatsAccumulator(agg) for agg in aggregations]
    )

    for r in records:
        # Build composite group key
        group_key = tuple(r.get(f, "NULL") for f in group_fields) if group_fields else ()
        accumulators = groups[group_key]

        for acc in accumulators:
            val = r.get(acc.field) if acc.field else None
            acc.update(val)

    # If records was empty and no group-by, output default 0 row
    if not records and not group_fields:
        row = {}
        for agg in aggregations:
            row[agg.as_name] = 0
        return [row]

    results = []
    for group_key, accumulators in groups.items():
        row: Dict[str, Any] = {}
        # Populate group-by fields
        for i, f in enumerate(group_fields):
            row[f] = group_key[i]

        # Populate aggregate values
        for acc in accumulators:
            row[acc.as_name] = acc.finalize()

        results.append(row)

    return results
