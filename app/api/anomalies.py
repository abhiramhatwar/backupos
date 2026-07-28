from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_tenant
from app.core.database import get_db
from app.models.anomaly import AnomalyAlert
from app.models.backup import BackupSnapshot
from app.models.policy import BackupPolicy, PolicyAttachment
from app.models.source import DataSource
from app.models.tenant import Tenant
from app.schemas.anomaly import AnomalyAlertResponse, ComplianceReport, ComplianceScore
from app.services.compliance_service import generate_report, score_source_compliance

router = APIRouter()


@router.get("", response_model=list[AnomalyAlertResponse])
async def list_anomalies(
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    """List all unresolved alerts for the current tenant."""
    stmt = (
        select(AnomalyAlert)
        .join(DataSource, AnomalyAlert.source_id == DataSource.id)
        .where(
            DataSource.tenant_id == tenant.id,
            AnomalyAlert.resolved == False,
        )
        .order_by(AnomalyAlert.created_at.desc())
    )
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/{source_id}", response_model=list[AnomalyAlertResponse])
async def list_source_anomalies(
    source_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    """List all alerts (resolved and unresolved) for a specific source."""
    # Verify ownership
    source_result = await db.execute(
        select(DataSource).where(
            DataSource.id == source_id,
            DataSource.tenant_id == tenant.id,
        )
    )
    if not source_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Data source not found")

    stmt = (
        select(AnomalyAlert)
        .where(AnomalyAlert.source_id == source_id)
        .order_by(AnomalyAlert.created_at.desc())
    )
    result = await db.execute(stmt)
    return result.scalars().all()


@router.post("/{alert_id}/resolve", response_model=AnomalyAlertResponse)
async def resolve_alert(
    alert_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    """Mark an anomaly alert as resolved."""
    stmt = (
        select(AnomalyAlert)
        .join(DataSource, AnomalyAlert.source_id == DataSource.id)
        .where(
            AnomalyAlert.id == alert_id,
            DataSource.tenant_id == tenant.id,
        )
    )
    result = await db.execute(stmt)
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.resolved = True
    alert.resolved_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(alert)
    return alert


# ---------------------------------------------------------------------------
# Compliance routes (still under /anomalies router, mounted at /api/v1/anomalies)
# ---------------------------------------------------------------------------


@router.get("/compliance/report", response_model=ComplianceReport)
async def compliance_report(
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    """Generate a full compliance report for all tenant sources."""
    sources_result = await db.execute(
        select(DataSource).where(DataSource.tenant_id == tenant.id)
    )
    sources = sources_result.scalars().all()

    # All unresolved alerts for the tenant
    alerts_stmt = (
        select(AnomalyAlert)
        .join(DataSource, AnomalyAlert.source_id == DataSource.id)
        .where(DataSource.tenant_id == tenant.id, AnomalyAlert.resolved == False)
    )
    all_alerts = (await db.execute(alerts_stmt)).scalars().all()
    alerts_by_source: dict[int, list] = {}
    for a in all_alerts:
        alerts_by_source.setdefault(a.source_id, []).append(a)

    source_scores = []
    for source in sources:
        # Attached policy
        policy_stmt = (
            select(BackupPolicy)
            .join(PolicyAttachment, PolicyAttachment.policy_id == BackupPolicy.id)
            .where(PolicyAttachment.source_id == source.id)
            .limit(1)
        )
        policy = (await db.execute(policy_stmt)).scalar_one_or_none()

        # Latest snapshot
        snap_stmt = (
            select(BackupSnapshot)
            .where(BackupSnapshot.source_id == source.id)
            .order_by(BackupSnapshot.created_at.desc())
            .limit(1)
        )
        last_snapshot = (await db.execute(snap_stmt)).scalar_one_or_none()

        score = score_source_compliance(
            source,
            policy,
            last_snapshot,
            alerts_by_source.get(source.id, []),
        )
        source_scores.append(score)

    report = generate_report(tenant.id, source_scores, all_alerts)
    return ComplianceReport(**report)


@router.get("/compliance/score")
async def compliance_score(
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    """Return the overall compliance score for the tenant."""
    sources_result = await db.execute(
        select(DataSource).where(DataSource.tenant_id == tenant.id)
    )
    sources = sources_result.scalars().all()

    if not sources:
        return {"tenant_id": tenant.id, "overall_score": 100.0, "source_count": 0}

    alerts_stmt = (
        select(AnomalyAlert)
        .join(DataSource, AnomalyAlert.source_id == DataSource.id)
        .where(DataSource.tenant_id == tenant.id, AnomalyAlert.resolved == False)
    )
    all_alerts = (await db.execute(alerts_stmt)).scalars().all()
    alerts_by_source: dict[int, list] = {}
    for a in all_alerts:
        alerts_by_source.setdefault(a.source_id, []).append(a)

    scores = []
    for source in sources:
        policy_stmt = (
            select(BackupPolicy)
            .join(PolicyAttachment, PolicyAttachment.policy_id == BackupPolicy.id)
            .where(PolicyAttachment.source_id == source.id)
            .limit(1)
        )
        policy = (await db.execute(policy_stmt)).scalar_one_or_none()

        snap_stmt = (
            select(BackupSnapshot)
            .where(BackupSnapshot.source_id == source.id)
            .order_by(BackupSnapshot.created_at.desc())
            .limit(1)
        )
        last_snapshot = (await db.execute(snap_stmt)).scalar_one_or_none()

        score = score_source_compliance(
            source,
            policy,
            last_snapshot,
            alerts_by_source.get(source.id, []),
        )
        scores.append(score["overall_score"])

    overall = sum(scores) / len(scores) if scores else 100.0
    return {
        "tenant_id": tenant.id,
        "overall_score": round(overall, 2),
        "source_count": len(sources),
    }
