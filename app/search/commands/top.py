"""
NIGHTWATCH — SPL 'top' and 'rare' Commands
Computes most and least frequent field values with count and percentage calculation.
"""

from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional


def execute_top_rare(
    records: List[Dict[str, Any]],
    field: str,
    limit: int = 10,
    by_fields: Optional[List[str]] = None,
    is_top: bool = True
) -> List[Dict[str, Any]]:
    if not records or not field:
        return []

    group_fields = by_fields or []

    # Map group_key -> Counter of field values
    grouped_counts = defaultdict(Counter)

    for r in records:
        group_key = tuple(r.get(f, "NULL") for f in group_fields) if group_fields else ()
        val = r.get(field, "NULL")
        grouped_counts[group_key][val] += 1

    results = []
    for group_key, val_counts in grouped_counts.items():
        total_for_group = sum(val_counts.values())
        if total_for_group == 0:
            continue

        # Sort values
        sorted_items = sorted(
            val_counts.items(),
            key=lambda item: item[1],
            reverse=is_top
        )

        for val, count in sorted_items[:limit]:
            row: Dict[str, Any] = {}
            for i, f in enumerate(group_fields):
                row[f] = group_key[i]
            row[field] = val
            row["count"] = count
            row["percent"] = round((count / total_for_group) * 100.0, 2)
            results.append(row)

    # Sort overall results by count
    results.sort(key=lambda r: r["count"], reverse=is_top)
    return results[:limit] if not group_fields else results
