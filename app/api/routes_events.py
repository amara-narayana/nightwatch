"""
NIGHTWATCH — Events and Investigation API Endpoints
"""

import json
import time
from collections import Counter
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Request

from app.services.investigation import get_investigation_service
from app.storage.engine import get_storage_engine

router = APIRouter(prefix="/api/events", tags=["Events"])


@router.post("/hec")
async def hec_post_route(request: Request):
    """
    Real-Time HTTP Event Collector (HEC) endpoint.
    Accepts single or batched JSON logs for instant real-time indexing.
    """
    try:
        body = await request.json()
    except Exception:
        raw_b = await request.body()
        body = {"event": raw_b.decode("utf-8", errors="replace")}
    return http_event_collector(body)


def http_event_collector(req_body: Any):
    """
    Core HEC event ingestion processor.
    """
    from datetime import datetime, timezone
    from app.models.event import NormalizedEvent

    storage = get_storage_engine()
    events_to_insert = []

    # Handle single dict or list of dicts
    items = req_body if isinstance(req_body, list) else [req_body]

    for item in items:
        if not isinstance(item, dict):
            continue

        raw_event = item.get("event")
        raw_str = json.dumps(raw_event) if isinstance(raw_event, (dict, list)) else str(raw_event or item)
        host = item.get("host", "hec-client")
        source = item.get("source", "http:hec")
        sourcetype = item.get("sourcetype", "json")
        index_name = item.get("index", "main")
        epoch_ts = float(item.get("time", time.time()))

        dt = datetime.fromtimestamp(epoch_ts, tz=timezone.utc)
        fields = item.get("fields", {})
        if isinstance(raw_event, dict):
            fields.update(raw_event)

        ev = NormalizedEvent.create(
            raw=raw_str,
            timestamp=dt,
            host=host,
            source=source,
            sourcetype=sourcetype,
            index_name=index_name,
            fields=fields
        )
        events_to_insert.append(ev)

    if events_to_insert:
        storage.insert_events_batch(events_to_insert)

    return {"text": "Success", "code": 0, "ingested_count": len(events_to_insert)}


@router.get("/{event_id}")
def get_event_details(event_id: int):
    """Retrieves full normalized event details by ID."""
    storage = get_storage_engine()
    event = storage.get_event_by_id(event_id)
    if not event:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found.")
    return event.to_record_dict()


@router.get("/investigate/timeline")
def investigate_entity_timeline(
    type: str = Query(..., pattern="^(ip|user|host|keyword)$"),
    value: str = Query(...),
    limit: int = Query(100, le=500)
):
    """Retrieves correlated chronological timeline for an entity."""
    inv = get_investigation_service()
    records = inv.get_entity_timeline(entity_type=type, entity_value=value, limit=limit)
    return {
        "entity_type": type,
        "entity_value": value,
        "count": len(records),
        "timeline": records
    }


@router.get("/summary/fields")
def get_field_summary(limit_events: int = Query(500, le=2000)):
    """
    Discovers fields and top values for the Splunk-style field sidebar.
    Returns field names, occurrence counts, and top 5 distinct values.
    """
    storage = get_storage_engine()
    with storage.get_connection() as conn:
        cur = conn.execute("SELECT * FROM events ORDER BY epoch DESC LIMIT ?;", (limit_events,))
        rows = cur.fetchall()

    field_counters: Dict[str, Counter] = {}

    for row in rows:
        rec = {
            "host": row["host"],
            "sourcetype": row["sourcetype"],
            "severity": row["severity"],
            "category": row["category"],
            "index": row["index_name"],
            "source": row["source"]
        }
        if row["fields_json"]:
            try:
                f_dict = json.loads(row["fields_json"])
                rec.update(f_dict)
            except Exception:
                pass

        for k, v in rec.items():
            if v is not None and v != "":
                if k not in field_counters:
                    field_counters[k] = Counter()
                field_counters[k][str(v)] += 1

    summary = []
    for field_name, counter in field_counters.items():
        total_occurrences = sum(counter.values())
        top_values = [{"value": val, "count": cnt} for val, cnt in counter.most_common(5)]
        summary.append({
            "name": field_name,
            "total_count": total_occurrences,
            "distinct_count": len(counter),
            "top_values": top_values
        })

    # Sort fields alphabetically
    summary.sort(key=lambda x: x["name"])
    return {
        "scanned_events": len(rows),
        "fields": summary
    }
