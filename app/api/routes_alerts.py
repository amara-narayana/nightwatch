"""
NIGHTWATCH — Alerts and Detection API Endpoints
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.detection.engine import get_detection_engine
from app.detection.rules import DetectionRuleRegistry
from app.models.alert import AlertStatus, DetectionRule, SecurityAlert
from app.services.investigation import get_investigation_service
from app.storage.engine import get_storage_engine

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


class UpdateAlertStatusRequest(BaseModel):
    status: str
    notes: Optional[str] = None


class UpdateRuleRequest(BaseModel):
    enabled: Optional[bool] = None
    threshold: Optional[int] = None
    severity: Optional[str] = None


@router.get("", response_model=List[SecurityAlert])
def list_alerts(
    status: Optional[str] = Query(None),
    limit: int = Query(100, le=500)
):
    """Lists security alerts with optional status filter."""
    storage = get_storage_engine()
    return storage.get_alerts(status=status, limit=limit)


@router.get("/{alert_id}")
def get_alert(alert_id: str):
    """Retrieves single alert and full evidence event details."""
    inv = get_investigation_service()
    res = inv.get_alert_evidence_events(alert_id)
    if "error" in res:
        raise HTTPException(status_code=404, detail=res["error"])
    return res


@router.patch("/{alert_id}/status")
def update_alert_status(alert_id: str, req: UpdateAlertStatusRequest):
    """Updates an alert's lifecycle status and investigation notes."""
    valid_statuses = [s.value for s in AlertStatus]
    if req.status.lower() not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{req.status}'. Must be one of: {valid_statuses}"
        )

    storage = get_storage_engine()
    updated = storage.update_alert_status(alert_id, req.status.lower(), req.notes)
    if not updated:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return {"id": alert_id, "status": req.status.lower(), "updated": True}


@router.post("/evaluate")
def trigger_detection_evaluation():
    """Manually triggers an immediate detection engine evaluation pass."""
    engine = get_detection_engine()
    new_alerts = engine.run_detection_cycle()
    return {"triggered": True, "new_alerts_count": new_alerts}


@router.get("/rules/list", response_model=List[DetectionRule])
def list_detection_rules():
    """Lists all configured security detection rules."""
    registry = DetectionRuleRegistry()
    return registry.get_all_rules()


@router.patch("/rules/{rule_id}")
def update_detection_rule(rule_id: str, req: UpdateRuleRequest):
    """Toggles or configures parameters for a detection rule."""
    registry = DetectionRuleRegistry()
    rule = registry.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found.")

    if req.enabled is not None:
        rule.enabled = req.enabled
    if req.threshold is not None:
        rule.threshold = req.threshold
    if req.severity is not None:
        rule.severity = req.severity.lower()

    registry.update_rule(rule)
    return {"rule_id": rule_id, "updated": True, "rule": rule}
