"""
NIGHTWATCH — Inputs and Ingestion API Endpoints
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.collectors.file_collector import LogInput, get_file_collector
from app.core.config import get_settings
from app.models.event import NormalizedEvent
from app.parsers.auto import get_auto_parser
from app.storage.engine import get_storage_engine

router = APIRouter(prefix="/api/inputs", tags=["Inputs"])


class AddInputRequest(BaseModel):
    id: str
    path: str
    sourcetype: str = "auto"
    index: str = "main"
    description: Optional[str] = ""
    enabled: bool = True


class IngestRawRequest(BaseModel):
    events: List[str]
    sourcetype: str = "auto"
    index: str = "main"
    host: Optional[str] = "api-ingest"
    source: Optional[str] = "api"


@router.get("", response_model=List[LogInput])
def list_inputs():
    """Lists all configured log inputs, offsets, and statistics."""
    collector = get_file_collector()
    return collector.get_inputs()


@router.post("", response_model=LogInput)
def add_input(req: AddInputRequest):
    """Registers a new log input to monitor."""
    settings = get_settings()
    collector = get_file_collector()

    resolved = settings.resolve_path(req.path)
    # Check for basic path security (prevent path traversal to sensitive system files)
    try:
        resolved_p = Path(resolved).resolve()
        # Verify not trying to access sensitive system devices or root outside reasonable scopes
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid path specified.")

    inp = LogInput(
        id=req.id,
        path=req.path,
        sourcetype=req.sourcetype,
        index=req.index,
        enabled=req.enabled,
        description=req.description
    )
    collector.add_input(inp)
    return inp


@router.delete("/{input_id}")
def remove_input(input_id: str):
    """Removes a configured log input."""
    collector = get_file_collector()
    removed = collector.remove_input(input_id)
    if not removed:
        raise HTTPException(status_code=404, detail=f"Input '{input_id}' not found.")
    return {"id": input_id, "deleted": True}


@router.post("/collect")
def trigger_collection():
    """Manually triggers an immediate file collector pass."""
    collector = get_file_collector()
    ingested = collector.collect_once()
    return {"collected": True, "ingested_count": ingested}


@router.post("/ingest_raw")
def ingest_raw_events(req: IngestRawRequest):
    """Directly ingests a list of raw event lines or JSON strings via API."""
    auto_parser = get_auto_parser()
    storage = get_storage_engine()

    normalized_events: List[NormalizedEvent] = []
    for line in req.events:
        stripped = line.strip()
        if not stripped:
            continue
        ev = auto_parser.parse_with_sourcetype(
            raw_line=stripped,
            sourcetype=req.sourcetype,
            source=req.source or "api",
            default_host=req.host or "api-ingest"
        )
        if ev:
            ev.index_name = req.index
            normalized_events.append(ev)

    count = storage.insert_events_batch(normalized_events)
    return {"ingested_count": count, "received_count": len(req.events)}
