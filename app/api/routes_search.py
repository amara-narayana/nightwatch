"""
NIGHTWATCH — Search API Endpoints
"""

import csv
import io
import json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Response
from pydantic import BaseModel

from app.models.event import QueryResult
from app.search.engine import get_search_engine
from app.search.parser import SPLParser

router = APIRouter(prefix="/api/search", tags=["Search"])


class SearchRequest(BaseModel):
    query: str
    earliest_epoch: Optional[float] = None
    latest_epoch: Optional[float] = None
    limit: Optional[int] = 1000


class ValidateResponse(BaseModel):
    valid: bool
    error: Optional[str] = None
    stages_count: int = 0


@router.post("", response_model=QueryResult)
def execute_search(req: SearchRequest):
    """Executes an SPL search query and returns structured results."""
    engine = get_search_engine()
    res = engine.execute(
        query_str=req.query,
        earliest_epoch=req.earliest_epoch,
        latest_epoch=req.latest_epoch,
        limit=req.limit
    )
    if res.status == "error":
        # Still return QueryResult with error field populated
        return res
    return res


@router.post("/validate", response_model=ValidateResponse)
def validate_query(req: SearchRequest):
    """Validates query syntax without executing retrieval."""
    parser = SPLParser()
    try:
        stage, commands = parser.parse(req.query)
        return ValidateResponse(
            valid=True,
            error=None,
            stages_count=1 + len(commands)
        )
    except Exception as e:
        return ValidateResponse(
            valid=False,
            error=str(e),
            stages_count=0
        )


@router.get("/export")
def export_search(
    query: str = Query(...),
    format: str = Query("csv", pattern="^(csv|json)$"),
    limit: int = Query(5000)
):
    """Exports search results in CSV or JSON format."""
    engine = get_search_engine()
    res = engine.execute(query_str=query, limit=limit)
    if res.status == "error":
        raise HTTPException(status_code=400, detail=res.error)

    if format == "json":
        data = json.dumps(res.records, indent=2)
        return Response(
            content=data,
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="nightwatch_export.json"'}
        )

    # CSV Export
    output = io.StringIO()
    if res.records:
        columns = res.columns or list(res.records[0].keys())
        writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for r in res.records:
            writer.writerow(r)

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="nightwatch_export.csv"'}
    )
