"""
NIGHTWATCH — Saved Searches and Search History Storage
"""

import time
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from app.storage.engine import get_storage_engine


class SavedSearch(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    query: str
    description: Optional[str] = ""
    created_at: float = Field(default_factory=time.time)
    last_run_at: Optional[float] = None
    run_count: int = 0


class SearchHistoryEntry(BaseModel):
    id: Optional[int] = None
    query: str
    executed_at: float
    duration_ms: float
    result_count: int
    status: str


class SavedSearchManager:
    def __init__(self):
        self.storage = get_storage_engine()

    def create_saved_search(self, name: str, query: str, description: str = "") -> SavedSearch:
        search_id = str(uuid.uuid4())
        now = time.time()
        with self.storage.get_connection() as conn:
            conn.execute("""
                INSERT INTO saved_searches (id, name, query, description, created_at, last_run_at, run_count)
                VALUES (?, ?, ?, ?, ?, NULL, 0)
                ON CONFLICT(name) DO UPDATE SET
                    query = excluded.query,
                    description = excluded.description;
            """, (search_id, name, query, description, now))
        return SavedSearch(id=search_id, name=name, query=query, description=description, created_at=now)

    def list_saved_searches(self) -> List[SavedSearch]:
        with self.storage.get_connection() as conn:
            cur = conn.execute("SELECT * FROM saved_searches ORDER BY name ASC;")
            return [
                SavedSearch(
                    id=row["id"],
                    name=row["name"],
                    query=row["query"],
                    description=row["description"],
                    created_at=row["created_at"],
                    last_run_at=row["last_run_at"],
                    run_count=row["run_count"]
                ) for row in cur.fetchall()
            ]

    def get_saved_search(self, name_or_id: str) -> Optional[SavedSearch]:
        with self.storage.get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM saved_searches WHERE id = ? OR name = ? LIMIT 1;",
                (name_or_id, name_or_id)
            )
            row = cur.fetchone()
            if not row:
                return None
            return SavedSearch(
                id=row["id"],
                name=row["name"],
                query=row["query"],
                description=row["description"],
                created_at=row["created_at"],
                last_run_at=row["last_run_at"],
                run_count=row["run_count"]
            )

    def record_run(self, name_or_id: str) -> None:
        now = time.time()
        with self.storage.get_connection() as conn:
            conn.execute("""
                UPDATE saved_searches
                SET run_count = run_count + 1, last_run_at = ?
                WHERE id = ? OR name = ?;
            """, (now, name_or_id, name_or_id))

    def delete_saved_search(self, name_or_id: str) -> bool:
        with self.storage.get_connection() as conn:
            cur = conn.execute(
                "DELETE FROM saved_searches WHERE id = ? OR name = ?;",
                (name_or_id, name_or_id)
            )
            return cur.rowcount > 0

    # --- Search History ---

    def log_search(self, query: str, duration_ms: float, result_count: int, status: str = "success") -> None:
        now = time.time()
        with self.storage.get_connection() as conn:
            conn.execute("""
                INSERT INTO search_history (query, executed_at, duration_ms, result_count, status)
                VALUES (?, ?, ?, ?, ?);
            """, (query, now, duration_ms, result_count, status))

            # Maintain maximum 1000 history records to avoid bloat
            conn.execute("""
                DELETE FROM search_history WHERE id NOT IN (
                    SELECT id FROM search_history ORDER BY id DESC LIMIT 1000
                );
            """)

    def get_search_history(self, limit: int = 50) -> List[SearchHistoryEntry]:
        with self.storage.get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM search_history ORDER BY id DESC LIMIT ?;",
                (limit,)
            )
            return [
                SearchHistoryEntry(
                    id=row["id"],
                    query=row["query"],
                    executed_at=row["executed_at"],
                    duration_ms=row["duration_ms"],
                    result_count=row["result_count"],
                    status=row["status"]
                ) for row in cur.fetchall()
            ]


_saved_search_manager: Optional[SavedSearchManager] = None


def get_saved_search_manager() -> SavedSearchManager:
    global _saved_search_manager
    if _saved_search_manager is None:
        _saved_search_manager = SavedSearchManager()
    return _saved_search_manager
