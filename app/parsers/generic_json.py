"""
NIGHTWATCH — Generic JSON Log Parser
Handles structured JSON logs from applications, web servers, and APIs.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from dateutil import parser as dt_parser

from app.models.event import NormalizedEvent
from app.normalization.cim import normalize_fields, normalize_severity
from app.parsers.base import BaseParser


class GenericJsonParser(BaseParser):
    def parse(self, raw_line: str, source: str = "unknown", default_host: str = "localhost") -> Optional[NormalizedEvent]:
        line = raw_line.strip()
        if not line:
            return None

        try:
            data = json.loads(line)
        except Exception:
            return None

        if not isinstance(data, dict):
            return None

        # Look for timestamp in common keys
        ts_val = None
        for k in ["timestamp", "@timestamp", "time", "date", "created_at", "datetime"]:
            if k in data:
                ts_val = data[k]
                break

        if ts_val:
            try:
                if isinstance(ts_val, (int, float)):
                    dt = datetime.fromtimestamp(ts_val, timezone.utc)
                else:
                    dt = dt_parser.parse(str(ts_val))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    else:
                        dt = dt.astimezone(timezone.utc)
            except Exception:
                dt = datetime.now(timezone.utc)
        else:
            dt = datetime.now(timezone.utc)

        # Host
        host = data.get("host") or data.get("hostname") or data.get("server") or default_host
        if isinstance(host, dict):
            host = host.get("name", default_host)

        # Severity
        sev_raw = data.get("severity") or data.get("level") or data.get("log_level") or "info"
        severity = normalize_severity(sev_raw)

        # Category
        category = data.get("category") or data.get("type") or "application"

        # Index
        index_name = data.get("index") or "main"

        # Extract remaining fields
        fields: Dict[str, Any] = {}
        for k, v in data.items():
            if k not in ["timestamp", "@timestamp", "raw", "_raw"]:
                fields[k] = v

        normalized = normalize_fields(fields)

        return NormalizedEvent.create(
            raw=raw_line,
            timestamp=dt,
            index_name=index_name,
            host=str(host),
            source=source,
            sourcetype="json",
            severity=severity,
            category=str(category),
            fields=normalized
        )
