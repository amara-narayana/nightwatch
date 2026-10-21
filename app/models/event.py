"""
NIGHTWATCH — Event Data Models
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class NormalizedEvent(BaseModel):
    id: Optional[int] = None
    timestamp: str  # ISO-8601 UTC string: e.g. "2026-10-21T05:30:00.123456Z"
    epoch: float    # Unix Epoch timestamp (seconds with microsecond fraction)
    index_name: str = "main"
    host: str = "localhost"
    source: str = "unknown"
    sourcetype: str = "generic"
    severity: str = "info"  # critical, high, medium, low, info
    category: str = "system"  # authentication, network, process, audit, system
    raw: str = ""   # original _raw event string
    fields: Dict[str, Any] = Field(default_factory=dict)

    def to_record_dict(self) -> Dict[str, Any]:
        """Flattens event for SPL pipeline processing and tabular display."""
        rec = {
            "id": self.id,
            "_time": self.timestamp,
            "timestamp": self.timestamp,
            "epoch": self.epoch,
            "index": self.index_name,
            "host": self.host,
            "source": self.source,
            "sourcetype": self.sourcetype,
            "severity": self.severity,
            "category": self.category,
            "_raw": self.raw,
            "raw": self.raw
        }
        # Flatten extracted fields directly into the record dictionary
        for k, v in self.fields.items():
            if k not in rec:
                rec[k] = v
        return rec

    @classmethod
    def create(
        cls,
        raw: str,
        timestamp: Optional[datetime] = None,
        index_name: str = "main",
        host: str = "localhost",
        source: str = "unknown",
        sourcetype: str = "generic",
        severity: str = "info",
        category: str = "system",
        fields: Optional[Dict[str, Any]] = None
    ) -> "NormalizedEvent":
        """Factory method with automatic timestamp and epoch calculation."""
        dt = timestamp or datetime.now(timezone.utc)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        iso_str = dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        epoch = dt.timestamp()

        return cls(
            id=None,
            timestamp=iso_str,
            epoch=epoch,
            index_name=index_name,
            host=host,
            source=source,
            sourcetype=sourcetype,
            severity=severity.lower(),
            category=category.lower(),
            raw=raw,
            fields=fields or {}
        )


class EventQuery(BaseModel):
    query: str
    earliest_epoch: Optional[float] = None
    latest_epoch: Optional[float] = None
    limit: int = 1000
    offset: int = 0


class QueryResult(BaseModel):
    query: str
    status: str = "success"  # success, error, timeout
    duration_ms: float
    total_scanned: int
    result_count: int
    columns: List[str]
    records: List[Dict[str, Any]]
    error: Optional[str] = None
    timeline_buckets: Optional[List[Dict[str, Any]]] = None
