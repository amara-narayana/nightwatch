"""
NIGHTWATCH — SPL 'head', 'tail', and 'dedup' Commands
"""

from typing import Any, Dict, List, Optional, Set, Tuple


def execute_head(records: List[Dict[str, Any]], count: int = 10) -> List[Dict[str, Any]]:
    return records[:max(0, count)]


def execute_tail(records: List[Dict[str, Any]], count: int = 10) -> List[Dict[str, Any]]:
    if count <= 0:
        return []
    return records[-count:]


def execute_dedup(
    records: List[Dict[str, Any]],
    fields: List[str],
    consecutive: bool = False
) -> List[Dict[str, Any]]:
    if not records or not fields:
        return records

    results = []
    seen_keys: Set[Tuple] = set()
    last_key: Optional[Tuple] = None

    for r in records:
        key = tuple(r.get(f) for f in fields)
        if consecutive:
            if key != last_key:
                results.append(r)
                last_key = key
        else:
            if key not in seen_keys:
                seen_keys.add(key)
                results.append(r)

    return results
