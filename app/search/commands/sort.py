"""
NIGHTWATCH — SPL 'sort' Command
Sorts records by one or multiple fields in ascending (+1) or descending (-1) order.
"""

from functools import cmp_to_key
from typing import Any, Dict, List, Tuple


def _compare_values(a: Any, b: Any) -> int:
    if a is None and b is None:
        return 0
    if a is None:
        return -1
    if b is None:
        return 1

    try:
        # Try numeric comparison
        num_a = float(a)
        num_b = float(b)
        if num_a < num_b:
            return -1
        elif num_a > num_b:
            return 1
        return 0
    except (ValueError, TypeError):
        pass

    str_a = str(a).lower()
    str_b = str(b).lower()
    if str_a < str_b:
        return -1
    elif str_a > str_b:
        return 1
    return 0


def execute_sort(records: List[Dict[str, Any]], sort_fields: List[Tuple[str, int]]) -> List[Dict[str, Any]]:
    if not records or not sort_fields:
        return records

    def comparator(rec1: Dict[str, Any], rec2: Dict[str, Any]) -> int:
        for field, direction in sort_fields:
            val1 = rec1.get(field)
            val2 = rec2.get(field)
            cmp_res = _compare_values(val1, val2)
            if cmp_res != 0:
                return cmp_res * direction
        return 0

    return sorted(records, key=cmp_to_key(comparator))
