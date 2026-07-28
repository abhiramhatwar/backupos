from datetime import datetime
from typing import Optional

from pydantic import BaseModel

from app.models.anomaly import AlertSeverity, AlertType


class AnomalyAlertResponse(BaseModel):
    id: int
    source_id: int
    alert_type: AlertType
    severity: AlertSeverity
    detail: Optional[str]
    metric_value: Optional[float]
    threshold_value: Optional[float]
    resolved: bool
    created_at: datetime
    resolved_at: Optional[datetime]

    model_config = {"from_attributes": True}


class ComplianceScore(BaseModel):
    source_id: int
    source_name: str
    overall_score: float
    soc2_score: float
    hipaa_score: float
    pci_score: float
    violations: list[str]
    last_evaluated: datetime


class ComplianceReport(BaseModel):
    tenant_id: int
    generated_at: datetime
    overall_score: float
    sources: list[ComplianceScore]
    total_violations: int
    critical_alerts: int
