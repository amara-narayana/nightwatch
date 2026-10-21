"""
NIGHTWATCH Forwarder — Versioned Event Data Model
Defines the strict normalized schema for all endpoint telemetry collected by NIGHTWATCH.
"""

import hashlib
import json
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field, field_validator

SCHEMA_VERSION = "1.0"
MAX_EVENT_SIZE_BYTES = 65536  # 64 KB limit per event
MAX_MESSAGE_SIZE_BYTES = 32768  # 32 KB limit for raw message payload


def generate_event_id(agent_id: str, source_type: str, source_name: str, record_id: str) -> str:
    """Generates a stable, reproducible SHA-256 event ID."""
    seed = f"{agent_id}:{source_type}:{source_name}:{record_id}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


class ForwarderEvent(BaseModel):
    """
    Standardized, versioned telemetry event schema emitted by NIGHTWATCH Forwarder agents.
    """
    schema_version: str = Field(default=SCHEMA_VERSION, description="Event specification schema version")
    event_id: str = Field(..., description="Stable, globally unique event identifier (SHA-256)")
    agent_id: str = Field(..., description="Unique identifier of the sending agent")
    hostname: str = Field(..., description="Endpoint hostname where the event occurred")
    platform: str = Field(..., description="Operating system platform ('windows', 'linux', 'darwin')")
    source_type: str = Field(..., description="Normalized source classification (e.g., 'winevt:system', 'linux:auth')")
    source_name: str = Field(..., description="Specific channel or log file path (e.g., 'System', '/var/log/auth.log')")
    event_timestamp: str = Field(..., description="Original event occurrence time in ISO-8601 UTC")
    observed_timestamp: str = Field(..., description="Time agent observed/collected the event in ISO-8601 UTC")
    message: str = Field(..., description="Raw message string or text payload")
    severity: Optional[str] = Field(default="info", description="Severity ('critical', 'high', 'medium', 'low', 'info')")
    source_event_id: Optional[str] = Field(default=None, description="Native event identifier (e.g., Windows Event ID 4624)")
    source_record_id: Optional[str] = Field(default=None, description="Native sequential record ID or byte offset")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Structured key-value fields parsed from the event")

    @field_validator("source_record_id", "source_event_id", mode="before")
    @classmethod
    def coerce_to_str(cls, v: Any) -> Optional[str]:
        if v is not None:
            return str(v)
        return None

    @field_validator("event_timestamp", "observed_timestamp")
    @classmethod
    def validate_timestamp(cls, v: str) -> str:
        try:
            # Must parse as ISO 8601
            datetime.fromisoformat(v.replace("Z", "+00:00"))
            return v
        except Exception as e:
            raise ValueError(f"Timestamp must be valid ISO-8601 format: {e}")

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: Optional[str]) -> str:
        allowed = {"critical", "high", "medium", "low", "info"}
        val = (v or "info").lower()
        if val not in allowed:
            return "info"
        return val

    @field_validator("message")
    @classmethod
    def validate_message(cls, v: str) -> str:
        if len(v.encode("utf-8")) > MAX_EVENT_SIZE_BYTES:
            raise ValueError(f"Message exceeds maximum allowed size ({MAX_EVENT_SIZE_BYTES} bytes)")
        return v

    def to_json(self) -> str:
        """Serializes event to canonical JSON string."""
        return json.dumps(self.model_dump(), separators=(',', ':'), ensure_ascii=False)

    def size_bytes(self) -> int:
        """Calculates memory/wire footprint of serialized event."""
        return len(self.to_json().encode("utf-8"))

    @classmethod
    def create(
        cls,
        agent_id: str,
        hostname: str,
        platform: str,
        source_type: str,
        source_name: str,
        message: str,
        event_timestamp: Optional[datetime] = None,
        severity: Optional[str] = "info",
        source_event_id: Optional[str] = None,
        source_record_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        custom_id_seed: Optional[str] = None
    ) -> "ForwarderEvent":
        """
        Factory to generate a valid ForwarderEvent with a stable, reproducible SHA-256 event_id.
        """
        now = datetime.now(timezone.utc)
        ev_dt = event_timestamp or now
        ev_iso = ev_dt.isoformat()
        obs_iso = now.isoformat()

        # Enforce size limits on raw message
        msg_bytes = message.encode("utf-8", errors="replace")
        if len(msg_bytes) > MAX_MESSAGE_SIZE_BYTES:
            message = msg_bytes[:MAX_MESSAGE_SIZE_BYTES].decode("utf-8", errors="ignore") + "... [TRUNCATED]"

        # Generate stable, unique event identifier
        # Uses source_name + source_record_id (if available) or source_name + event_timestamp + seed/hash
        if custom_id_seed:
            seed = custom_id_seed
        elif source_record_id:
            seed = f"{agent_id}:{source_type}:{source_name}:{source_record_id}"
        else:
            seed = f"{agent_id}:{source_type}:{source_name}:{ev_iso}:{hashlib.sha256(message.encode('utf-8')).hexdigest()[:16]}"

        event_id = hashlib.sha256(seed.encode("utf-8")).hexdigest()

        return cls(
            schema_version=SCHEMA_VERSION,
            event_id=event_id,
            agent_id=agent_id,
            hostname=hostname,
            platform=platform.lower(),
            source_type=source_type,
            source_name=source_name,
            event_timestamp=ev_iso,
            observed_timestamp=obs_iso,
            message=message,
            severity=severity or "info",
            source_event_id=str(source_event_id) if source_event_id is not None else None,
            source_record_id=str(source_record_id) if source_record_id is not None else None,
            metadata=metadata or {}
        )
