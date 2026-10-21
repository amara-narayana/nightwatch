"""
NIGHTWATCH — Saved Searches & Search History API Endpoints
"""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.storage.saved_searches import SavedSearch, SearchHistoryEntry, get_saved_search_manager

router = APIRouter(prefix="/api/saved_searches", tags=["Saved Searches"])


class CreateSavedSearchRequest(BaseModel):
    name: str
    query: str
    description: Optional[str] = ""


@router.get("", response_model=List[SavedSearch])
def list_saved_searches():
    """Returns all saved searches."""
    mgr = get_saved_search_manager()
    return mgr.list_saved_searches()


@router.post("", response_model=SavedSearch)
def create_saved_search(req: CreateSavedSearchRequest):
    """Creates or updates a saved search."""
    mgr = get_saved_search_manager()
    return mgr.create_saved_search(name=req.name, query=req.query, description=req.description)


@router.delete("/{name_or_id}")
def delete_saved_search(name_or_id: str):
    """Deletes a saved search."""
    mgr = get_saved_search_manager()
    deleted = mgr.delete_saved_search(name_or_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Saved search '{name_or_id}' not found.")
    return {"id": name_or_id, "deleted": True}


@router.get("/history/list", response_model=List[SearchHistoryEntry])
def get_search_history(limit: int = Query(50, le=200)):
    """Returns recent executed queries and performance metrics."""
    mgr = get_saved_search_manager()
    return mgr.get_search_history(limit=limit)
