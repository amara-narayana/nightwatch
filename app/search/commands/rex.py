"""
NIGHTWATCH — SPL 'rex' and 'spath' Commands
Provides dynamic regex extraction and structured JSON path traversal at search time.
"""

import json
import re
from typing import Any, Dict, List, Optional


def execute_rex(
    records: List[Dict[str, Any]],
    pattern: str,
    field: str = "_raw"
) -> List[Dict[str, Any]]:
    if not pattern or not records:
        return records

    # Normalize (?<name>...) to Python's (?P<name>...)
    py_pattern = re.sub(r"\(\?<([a-zA-Z0-9_]+)>", r"(?P<\1>", pattern)
    try:
        compiled_regex = re.compile(py_pattern)
    except Exception as e:
        # Invalid regex, return records untouched
        return records

    for r in records:
        target_val = str(r.get(field, ""))
        m = compiled_regex.search(target_val)
        if m:
            group_dict = m.groupdict()
            for k, v in group_dict.items():
                if v is not None:
                    r[k] = v

    return records


def execute_spath(
    records: List[Dict[str, Any]],
    path: str,
    input_field: str = "_raw",
    output_field: Optional[str] = None
) -> List[Dict[str, Any]]:
    if not path or not records:
        return records

    out_key = output_field or path.split(".")[-1]
    keys = path.split(".")

    for r in records:
        val = r.get(input_field)
        curr = None
        if isinstance(val, str):
            try:
                curr = json.loads(val)
            except Exception:
                start_obj = val.find("{")
                end_obj = val.rfind("}")
                if start_obj != -1 and end_obj > start_obj:
                    try:
                        curr = json.loads(val[start_obj:end_obj + 1])
                    except Exception:
                        pass
        elif isinstance(val, (dict, list)):
            curr = val

        # Navigate nested path
        for k in keys:
            if isinstance(curr, dict) and k in curr:
                curr = curr[k]
            elif isinstance(curr, list) and k.isdigit():
                idx = int(k)
                if 0 <= idx < len(curr):
                    curr = curr[idx]
                else:
                    curr = None
                    break
            else:
                curr = None
                break

        if curr is not None:
            r[out_key] = curr

    return records
