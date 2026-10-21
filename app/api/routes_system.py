"""
NIGHTWATCH — System Health & Retention API Endpoints
"""

from typing import Any, Dict
from fastapi import APIRouter
from pydantic import BaseModel

from app.core.config import get_settings
from app.services.health import get_health_service
from app.services.retention import get_retention_service

router = APIRouter(prefix="/api/system", tags=["System"])


@router.get("/health")
def get_system_health():
    """Returns real-time host and process health, memory budgets, and storage status."""
    health_svc = get_health_service()
    return health_svc.get_system_telemetry()


@router.post("/retention/run")
def trigger_retention():
    """Manually triggers data retention pruning according to configured policies."""
    retention_svc = get_retention_service()
    return retention_svc.run_retention_cycle()


@router.get("/info")
def get_system_info():
    """Returns product title, version, and platform metadata."""
    settings = get_settings()
    return {
        "name": settings.app_name,
        "title": settings.app_title,
        "version": settings.version,
        "mode": "standalone_local",
        "description": "Lightweight Security Intelligence Platform"
    }
