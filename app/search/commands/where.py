"""
NIGHTWATCH — SPL 'where' Command
Safely evaluates filtering conditions without using arbitrary Python eval().
"""

import fnmatch
import re
from typing import Any, Dict, Iterator, List


class WhereEvaluator:
    @classmethod
    def evaluate(cls, expression: str, record: Dict[str, Any]) -> bool:
        """
        Safely evaluates boolean condition against record.
        Supports:
        - field op value (e.g. severity == "high", count > 5, status != 200)
        - like(field, "pattern")
        - isnull(field) / isnotnull(field)
        - compound AND / OR
        """
        expr = expression.strip()
        if not expr:
            return True

        # Handle OR
        or_parts = re.split(r"\s+OR\s+", expr, flags=re.IGNORECASE)
        if len(or_parts) > 1:
            return any(cls.evaluate(part, record) for part in or_parts)

        # Handle AND
        and_parts = re.split(r"\s+AND\s+", expr, flags=re.IGNORECASE)
        if len(and_parts) > 1:
            return all(cls.evaluate(part, record) for part in and_parts)

        # Handle isnull(field)
        m_null = re.match(r"^isnull\((.+)\)$", expr, re.IGNORECASE)
        if m_null:
            field = m_null.group(1).strip()
            return field not in record or record[field] is None or record[field] == ""

        # Handle isnotnull(field)
        m_notnull = re.match(r"^isnotnull\((.+)\)$", expr, re.IGNORECASE)
        if m_notnull:
            field = m_notnull.group(1).strip()
            return field in record and record[field] is not None and record[field] != ""

        # Handle like(field, "pattern")
        m_like = re.match(r'^like\(([^,]+),\s*["\'](.*)["\']\)$', expr, re.IGNORECASE)
        if m_like:
            field = m_like.group(1).strip()
            pattern = m_like.group(2).strip()
            val = str(record.get(field, ""))
            # Convert SQL % wildcard to glob *
            glob_pat = pattern.replace("%", "*").replace("_", "?")
            return fnmatch.fnmatch(val, glob_pat)

        # Handle binary comparison: left op right
        m_comp = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*(==|!=|>=|<=|>|<|=)\s*(.+)$', expr)
        if m_comp:
            field = m_comp.group(1).strip()
            op = m_comp.group(2).strip()
            if op == "==":
                op = "="
            raw_target = m_comp.group(3).strip()

            target_val = cls._parse_val(raw_target, record)
            actual_val = record.get(field)

            return cls._compare(actual_val, op, target_val)

        return True

    @classmethod
    def _parse_val(cls, raw: str, record: Dict[str, Any]) -> Any:
        # Check quoted string
        if (raw.startswith('"') and raw.endswith('"')) or (raw.startswith("'") and raw.endswith("'")):
            return raw[1:-1]
        # Check if reference to another field
        if raw in record:
            return record[raw]
        # Check number
        try:
            if "." in raw:
                return float(raw)
            return int(raw)
        except Exception:
            return raw

    @classmethod
    def _compare(cls, actual: Any, op: str, target: Any) -> bool:
        if actual is None:
            if op == "!=":
                return target is not None
            if op == "=":
                return target is None
            return False

        # Try numeric comparison if possible
        try:
            num_actual = float(actual)
            num_target = float(target)
            if op == "=":
                return num_actual == num_target
            elif op == "!=":
                return num_actual != num_target
            elif op == ">":
                return num_actual > num_target
            elif op == "<":
                return num_actual < num_target
            elif op == ">=":
                return num_actual >= num_target
            elif op == "<=":
                return num_actual <= num_target
        except Exception:
            pass

        # String / Fallback comparison
        str_actual = str(actual).lower()
        str_target = str(target).lower()

        if op == "=":
            return str_actual == str_target
        elif op == "!=":
            return str_actual != str_target
        elif op == ">":
            return str_actual > str_target
        elif op == "<":
            return str_actual < str_target
        elif op == ">=":
            return str_actual >= str_target
        elif op == "<=":
            return str_actual <= str_target

        return False


def execute_where(records: List[Dict[str, Any]], expression: str) -> List[Dict[str, Any]]:
    return [r for r in records if WhereEvaluator.evaluate(expression, r)]
