"""
NIGHTWATCH — Investigation Service
Pivots on entities (IPs, Users, Hosts) and resolves alert evidence to full event records.
"""

from typing import Any, Dict, List, Optional
from app.models.alert import SecurityAlert
from app.models.event import NormalizedEvent
from app.storage.engine import get_storage_engine


class InvestigationService:
    def __init__(self):
        self.storage = get_storage_engine()

    def get_entity_timeline(
        self,
        entity_type: str,
        entity_value: str,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Retrieves chronological timeline of events involving an IP, user, or host across all indices.
        """
        norm_type = entity_type.lower().strip()
        val = entity_value.strip()

        with self.storage.get_connection() as conn:
            if norm_type in ("ip", "src_ip", "dest_ip"):
                # Search host or JSON fields src_ip / dest_ip or raw text
                sql = """
                    SELECT * FROM events
                    WHERE host = ?
                       OR json_extract(fields_json, '$.src_ip') = ?
                       OR json_extract(fields_json, '$.dest_ip') = ?
                       OR id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)
                    ORDER BY epoch DESC
                    LIMIT ?;
                """
                cur = conn.execute(sql, (val, val, val, f'"{val}"', limit))
            elif norm_type in ("user", "username"):
                sql = """
                    SELECT * FROM events
                    WHERE json_extract(fields_json, '$.user') = ?
                       OR id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)
                    ORDER BY epoch DESC
                    LIMIT ?;
                """
                cur = conn.execute(sql, (val, f'"{val}"', limit))
            elif norm_type == "host":
                sql = """
                    SELECT * FROM events
                    WHERE host = ?
                       OR id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)
                    ORDER BY epoch DESC
                    LIMIT ?;
                """
                cur = conn.execute(sql, (val, f'"{val}"', limit))
            else:
                # Fallback to FTS
                sql = """
                    SELECT * FROM events
                    WHERE id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)
                    ORDER BY epoch DESC
                    LIMIT ?;
                """
                cur = conn.execute(sql, (f'"{val}"', limit))

            rows = cur.fetchall()
            return [self.storage._row_to_event(r).to_record_dict() for r in rows]

    def get_alert_evidence_events(self, alert_id: str) -> Dict[str, Any]:
        """Resolves alert and fetches full original raw events referenced in its evidence."""
        alert = self.storage.get_alert_by_id(alert_id)
        if not alert:
            return {"error": "Alert not found", "events": []}

        event_ids = []
        for ev in alert.evidence:
            if isinstance(ev, dict) and "id" in ev and ev["id"] is not None:
                event_ids.append(ev["id"])

        events = []
        if event_ids:
            placeholders = ",".join("?" for _ in event_ids)
            sql = f"SELECT * FROM events WHERE id IN ({placeholders}) ORDER BY epoch ASC;"
            with self.storage.get_connection() as conn:
                cur = conn.execute(sql, tuple(event_ids))
                for row in cur.fetchall():
                    events.append(self.storage._row_to_event(row).to_record_dict())

        return {
            "alert": alert.model_dump(),
            "evidence_events": events,
            "evidence_count": len(events)
        }


_investigation_service: Optional[InvestigationService] = None


def get_investigation_service() -> InvestigationService:
    global _investigation_service
    if _investigation_service is None:
        _investigation_service = InvestigationService()
    return _investigation_service
