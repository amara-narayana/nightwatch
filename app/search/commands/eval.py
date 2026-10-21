"""
NIGHTWATCH — SPL 'eval' Command
Evaluates calculated fields, arithmetic, conditionals, and string functions without arbitrary python eval().
"""

import math
import re
from typing import Any, Dict, List
from app.search.commands.where import WhereEvaluator


class EvalEvaluator:
    @classmethod
    def evaluate(cls, expr: str, record: Dict[str, Any]) -> Any:
        expr = expr.strip()
        if not expr:
            return None

        # 1. Handle if(cond, true_val, false_val)
        m_if = re.match(r'^if\((.+?),\s*(.+?),\s*(.+?)\)$', expr, re.IGNORECASE)
        if m_if:
            cond_str = m_if.group(1).strip()
            true_expr = m_if.group(2).strip()
            false_expr = m_if.group(3).strip()

            if WhereEvaluator.evaluate(cond_str, record):
                return cls.evaluate(true_expr, record)
            else:
                return cls.evaluate(false_expr, record)

        # 2. Handle coalesce(a, b, c)
        m_coal = re.match(r'^coalesce\((.+)\)$', expr, re.IGNORECASE)
        if m_coal:
            args = [a.strip() for a in m_coal.group(1).split(",")]
            for arg in args:
                val = cls.evaluate(arg, record)
                if val is not None and val != "":
                    return val
            return None

        # 3. Handle string functions: lower(), upper(), len(), tostring(), tonumber()
        m_fn = re.match(r'^(lower|upper|len|tostring|tonumber)\((.+)\)$', expr, re.IGNORECASE)
        if m_fn:
            fn_name = m_fn.group(1).lower()
            inner_arg = m_fn.group(2).strip()
            val = cls.evaluate(inner_arg, record)
            if fn_name == "lower":
                return str(val).lower() if val is not None else ""
            elif fn_name == "upper":
                return str(val).upper() if val is not None else ""
            elif fn_name == "len":
                return len(str(val)) if val is not None else 0
            elif fn_name == "tostring":
                return str(val) if val is not None else ""
            elif fn_name == "tonumber":
                try:
                    return float(val) if "." in str(val) else int(val)
                except Exception:
                    return 0

        # 4. Handle string concatenation: arg1 . arg2 . arg3
        if " . " in expr:
            parts = expr.split(" . ")
            return "".join(str(cls.evaluate(p.strip(), record) or "") for p in parts)

        # 5. Handle arithmetic operations: +, -, *, /
        # Check if contains arithmetic operators
        for op in ("+", "-", "*", "/"):
            pattern = rf"^(.+?)\s*\{op}\s*(.+)$"
            m_op = re.match(pattern, expr)
            if m_op:
                left = cls.evaluate(m_op.group(1).strip(), record)
                right = cls.evaluate(m_op.group(2).strip(), record)
                try:
                    num_l = float(left)
                    num_r = float(right)
                    if op == "+":
                        res = num_l + num_r
                    elif op == "-":
                        res = num_l - num_r
                    elif op == "*":
                        res = num_l * num_r
                    elif op == "/":
                        res = num_l / num_r if num_r != 0 else 0.0
                    return round(res, 4) if res != int(res) else int(res)
                except Exception:
                    pass

        # 6. Literal Quoted String
        if (expr.startswith('"') and expr.endswith('"')) or (expr.startswith("'") and expr.endswith("'")):
            return expr[1:-1]

        # 7. Field Reference
        if expr in record:
            return record[expr]

        # 8. Numeric Literal
        try:
            if "." in expr:
                return float(expr)
            return int(expr)
        except Exception:
            pass

        return expr


def execute_eval(records: List[Dict[str, Any]], target_field: str, expression: str) -> List[Dict[str, Any]]:
    for r in records:
        r[target_field] = EvalEvaluator.evaluate(expression, r)
    return records
