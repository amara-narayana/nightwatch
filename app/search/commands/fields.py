"""
NIGHTWATCH — SPL 'fields' and 'table' Commands
"""

from typing import Any, Dict, List


def execute_fields(records: List[Dict[str, Any]], fields: List[str], mode: str = "+") -> List[Dict[str, Any]]:
    if not fields:
        return records

    field_set = set(fields)
    results = []

    if mode == "-":
        # Exclusion
        for r in records:
            results.append({k: v for k, v in r.items() if k not in field_set})
    else:
        # Inclusion (always keep internal _time / id if present)
        for r in records:
            filtered = {}
            for f in fields:
                if f in r:
                    filtered[f] = r[f]
            results.append(filtered)

    return results


def execute_table(records: List[Dict[str, Any]], columns: List[str]) -> List[Dict[str, Any]]:
    if not columns:
        return records

    results = []
    for r in records:
        row = {}
        for col in columns:
            row[col] = r.get(col, None)
        results.append(row)
    return results
