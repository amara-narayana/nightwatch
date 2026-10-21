"""
NIGHTWATCH — Security Alert and Detection Models
"""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AlertStatus(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"


class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SecurityAlert(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str
    rule_name: str
    severity: str = "high"
    category: str = "security"
    description: str
    triggered_at: str
    triggered_epoch: float
    status: str = AlertStatus.NEW.value
    event_count: int = 1
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    resolution_notes: Optional[str] = None
    updated_at: float = Field(default_factory=lambda: datetime.now(timezone.utc).timestamp())

    @classmethod
    def create(
        cls,
        rule_id: str,
        rule_name: str,
        description: str,
        severity: str = "high",
        category: str = "security",
        event_count: int = 1,
        evidence: Optional[List[Dict[str, Any]]] = None
    ) -> "SecurityAlert":
        now = datetime.now(timezone.utc)
        return cls(
            id=str(uuid.uuid4()),
            rule_id=rule_id,
            rule_name=rule_name,
            severity=severity.lower(),
            category=category.lower(),
            description=description,
            triggered_at=now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            triggered_epoch=now.timestamp(),
            status=AlertStatus.NEW.value,
            event_count=event_count,
            evidence=evidence or [],
            resolution_notes=None,
            updated_at=now.timestamp()
        )


class DetectionRule(BaseModel):
    id: str
    name: str
    description: str
    severity: str = "high"
    category: str = "security"
    enabled: bool = True
    rule_type: str = "threshold"  # threshold, distinct_threshold, sequence, privileged_target, ids_alert, regex_pattern
    time_window_seconds: int = 300
    threshold: int = 5
    group_by: Optional[str] = "src_ip"
    distinct_field: Optional[str] = None
    conditions: Dict[str, Any] = Field(default_factory=dict)
    privileged_users: List[str] = Field(default_factory=list)
    regex: Optional[str] = None
    failure_threshold: Optional[int] = None
    suppression_window_seconds: int = 900
