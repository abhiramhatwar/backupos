from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_event
from app.core.auth import get_current_tenant
from app.core.database import get_db
from app.core.rate_limit import enforce_rate_limit
from app.models.backup import BackupJob, BackupSnapshot, JobStatus
from app.models.policy import BackupPolicy, PolicyAttachment
from app.models.source import DataSource
from app.models.tenant import Tenant
from app.schemas.backup import BackupJobCreate, BackupJobResponse, RecoveryMetrics, SnapshotResponse

router = APIRouter()


@router.post("", response_model=BackupJobResponse, status_code=status.HTTP_201_CREATED)
async def trigger_backup(
    payload: BackupJobCreate,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    await enforce_rate_limit(tenant.id)

    # Verify source ownership
    source_result = await db.execute(
        select(DataSource).where(
            DataSource.id == payload.source_id,
            DataSource.tenant_id == tenant.id,
        )
    )
    source = source_result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Data source not found")

    job = BackupJob(
        source_id=source.id,
        backup_type=payload.backup_type,
        status=JobStatus.pending,
    )
    db.add(job)
    await log_event(db, tenant.id, "backup.triggered", "BackupJob", None, tenant.email,
                    detail=f"type={payload.backup_type.value} source={source.id}")
    await db.commit()
    await db.refresh(job)

    # Dispatch Celery task (import lazily to avoid circular imports at startup)
    try:
        from app.workers.backup_worker import run_backup

        task = run_backup.delay(job.id, source.path, source.id, payload.backup_type.value)
        job.celery_task_id = task.id
        await db.commit()
        await db.refresh(job)
    except Exception:
        # If Celery / Redis is unavailable mark job failed but still return it
        job.status = JobStatus.failed
        job.error_message = "Failed to dispatch backup task (broker unavailable)"
        await db.commit()
        await db.refresh(job)

    return job


@router.get("", response_model=list[BackupJobResponse])
async def list_backups(
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    stmt = (
        select(BackupJob)
        .join(DataSource, BackupJob.source_id == DataSource.id)
        .where(DataSource.tenant_id == tenant.id)
        .order_by(BackupJob.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/{job_id}", response_model=BackupJobResponse)
async def get_backup(
    job_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    stmt = (
        select(BackupJob)
        .join(DataSource, BackupJob.source_id == DataSource.id)
        .where(BackupJob.id == job_id, DataSource.tenant_id == tenant.id)
    )
    result = await db.execute(stmt)
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Backup job not found")
    return job


@router.get("/{source_id}/history", response_model=list[SnapshotResponse])
async def source_history(
    source_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    source_result = await db.execute(
        select(DataSource).where(
            DataSource.id == source_id,
            DataSource.tenant_id == tenant.id,
        )
    )
    if not source_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Data source not found")

    stmt = (
        select(BackupSnapshot)
        .where(BackupSnapshot.source_id == source_id)
        .order_by(BackupSnapshot.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    result = await db.execute(stmt)
    return [SnapshotResponse.from_orm_with_ratio(s) for s in result.scalars().all()]


@router.get("/{source_id}/recovery-metrics", response_model=RecoveryMetrics)
async def recovery_metrics(
    source_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    # Verify ownership
    source_result = await db.execute(
        select(DataSource).where(
            DataSource.id == source_id,
            DataSource.tenant_id == tenant.id,
        )
    )
    source = source_result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Data source not found")

    # Last completed job
    last_job_stmt = (
        select(BackupJob)
        .where(
            BackupJob.source_id == source_id,
            BackupJob.status == JobStatus.completed,
        )
        .order_by(BackupJob.completed_at.desc())
        .limit(1)
    )
    last_job = (await db.execute(last_job_stmt)).scalar_one_or_none()

    # Latest snapshot
    latest_snapshot_stmt = (
        select(BackupSnapshot)
        .where(BackupSnapshot.source_id == source_id)
        .order_by(BackupSnapshot.created_at.desc())
        .limit(1)
    )
    latest_snapshot = (await db.execute(latest_snapshot_stmt)).scalar_one_or_none()

    # Count total snapshots via aggregate — avoids loading all rows into memory
    count_result = await db.execute(
        select(func.count(BackupSnapshot.id)).where(BackupSnapshot.source_id == source_id)
    )
    total_snapshots = count_result.scalar_one()

    # Attached policy for RPO comparison
    policy_stmt = (
        select(BackupPolicy)
        .join(PolicyAttachment, PolicyAttachment.policy_id == BackupPolicy.id)
        .where(PolicyAttachment.source_id == source_id)
        .limit(1)
    )
    policy = (await db.execute(policy_stmt)).scalar_one_or_none()

    now = datetime.now(timezone.utc)
    current_rpo_minutes: Optional[float] = None
    rpo_violated = False
    last_successful_backup: Optional[datetime] = None

    if last_job and last_job.completed_at:
        completed_at = last_job.completed_at
        if completed_at.tzinfo is None:
            completed_at = completed_at.replace(tzinfo=timezone.utc)
        last_successful_backup = completed_at
        current_rpo_minutes = (now - completed_at).total_seconds() / 60
        if policy and current_rpo_minutes > policy.rpo_minutes:
            rpo_violated = True

    # RTO estimate: total_size / restore_throughput (assume 100 MB/s)
    estimated_rto_minutes: Optional[float] = None
    if latest_snapshot and latest_snapshot.total_size_bytes > 0:
        restore_bytes_per_minute = 100 * 1024 * 1024  # 100 MB/s
        estimated_rto_minutes = round(latest_snapshot.total_size_bytes / restore_bytes_per_minute, 4)

    return RecoveryMetrics(
        source_id=source_id,
        last_successful_backup=last_successful_backup,
        current_rpo_minutes=current_rpo_minutes,
        policy_rpo_minutes=policy.rpo_minutes if policy else None,
        rpo_violated=rpo_violated,
        estimated_rto_minutes=estimated_rto_minutes,
        total_snapshots=total_snapshots,
        latest_snapshot_id=latest_snapshot.id if latest_snapshot else None,
        latest_merkle_root=latest_snapshot.merkle_root if latest_snapshot else None,
    )
