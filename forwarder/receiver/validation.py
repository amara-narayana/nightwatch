"""
NIGHTWATCH Forwarder Receiver — Event & Payload Validation
Validates incoming frame envelopes, event data types, size limits, and schemas.
"""

from typing import Any, Dict, List, Optional, Tuple

REQUIRED_EVENT_FIELDS = [
    "schema_version",
    "event_id",
    "agent_id",
    "hostname",
    "platform",
    "source_type",
    "source_name",
    "event_timestamp",
    "observed_timestamp",
    "message"
]

MAX_BATCH_EVENTS = 5000
MAX_EVENT_SIZE = 65536  # 64 KB


class ValidationError(Exception):
    """Raised when an incoming event or batch payload violates schema rules."""
    pass


def validate_batch_envelope(payload: Dict[str, Any]) -> Tuple[str, str, List[Dict[str, Any]]]:
    """
    Validates the top-level batch structure.
    Returns (batch_id, agent_id, events_list).
    """
    batch_id = payload.get("batch_id")
    if not batch_id or not isinstance(batch_id, str):
        raise ValidationError("Missing or invalid 'batch_id' in event batch payload")

    agent_id = payload.get("agent_id")
    if not agent_id or not isinstance(agent_id, str):
        raise ValidationError("Missing or invalid 'agent_id' in event batch payload")

    events = payload.get("events")
    if not isinstance(events, list):
        raise ValidationError("Missing or invalid 'events' array in event batch payload")

    if len(events) > MAX_BATCH_EVENTS:
        raise ValidationError(f"Batch event count ({len(events)}) exceeds maximum limit ({MAX_BATCH_EVENTS})")

    return batch_id, agent_id, events


def validate_event_dict(ev: Dict[str, Any]) -> None:
    """
    Validates a single event dictionary against the required schema.
    """
    if not isinstance(ev, dict):
        raise ValidationError("Event item must be a JSON object")

    for f in REQUIRED_EVENT_FIELDS:
        if f not in ev or ev[f] is None or ev[f] == "":
            raise ValidationError(f"Event missing required field: '{f}'")

    if not isinstance(ev["event_id"], str) or len(ev["event_id"]) < 8:
        raise ValidationError("Invalid 'event_id' format")

    if not isinstance(ev["message"], str):
        raise ValidationError("Field 'message' must be a string")

    if len(ev["message"]) > 100000:
        raise ValidationError("Field 'message' exceeds max length limit")
