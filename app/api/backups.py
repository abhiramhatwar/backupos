from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_event
from app.core.auth import get_current_tenant
from app.core.database import get_db
from app.core.rate_limit import enforce_rate_limit
from app.models.backup import BackupJob, BackupSnapshot, BackupType, JobStatus, SnapshotFile
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


class SynthesizeResponse(BaseModel):
    synthetic_snapshot_id: int
    source_id: int
    merkle_root: str
    total_size_bytes: int
    chunk_count: int
    file_count: int
    created_at: object
    message: str


@router.post("/{source_id}/synthesize-full", response_model=SynthesizeResponse, status_code=status.HTTP_201_CREATED)
async def synthesize_full_backup(
    source_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    """
    Synthesize a self-contained full backup snapshot from the incremental chain.

    Performs a metadata-only merge of SnapshotFile manifests from the latest
    snapshot into a new synthetic full snapshot — no CAS I/O required.  The
    resulting snapshot has no parent_snapshot_id, making it a valid recovery
    point that does not depend on the prior incremental chain.  This is the
    same technique used by enterprise backup systems to periodically re-base
    their incremental chains without re-reading source data.
    """
    source_result = await db.execute(
        select(DataSource).where(
            DataSource.id == source_id,
            DataSource.tenant_id == tenant.id,
        )
    )
    source = source_result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Data source not found")

    latest_stmt = (
        select(BackupSnapshot)
        .where(BackupSnapshot.source_id == source_id)
        .order_by(BackupSnapshot.created_at.desc())
        .limit(1)
    )
    latest = (await db.execute(latest_stmt)).scalar_one_or_none()
    if not latest:
        raise HTTPException(status_code=404, detail="No snapshots found — run a backup first")

    files_result = await db.execute(
        select(SnapshotFile)
        .where(SnapshotFile.snapshot_id == latest.id)
        .order_by(SnapshotFile.id)
    )
    file_records = files_result.scalars().all()

    if not file_records:
        raise HTTPException(
            status_code=422,
            detail="Latest snapshot has no file records — cannot synthesize",
        )

    from app.core.merkle import MerkleTree

    all_hashes = [h for sf in file_records for h in sf.get_chunk_hashes()]
    merkle_root = MerkleTree(all_hashes).root_hash

    now = datetime.now(timezone.utc)
    synth_job = BackupJob(
        source_id=source_id,
        backup_type=BackupType.full,
        status=JobStatus.completed,
        started_at=now,
        completed_at=now,
    )
    db.add(synth_job)
    await db.flush()

    synth_snapshot = BackupSnapshot(
        job_id=synth_job.id,
        source_id=source_id,
        merkle_root=merkle_root,
        parent_snapshot_id=None,
        total_size_bytes=latest.total_size_bytes,
        dedup_size_bytes=latest.dedup_size_bytes,
        chunk_count=len(all_hashes),
        new_chunk_count=0,
        average_entropy=latest.average_entropy,
    )
    db.add(synth_snapshot)
    await db.flush()

    for sf in file_records:
        db.add(SnapshotFile(
            snapshot_id=synth_snapshot.id,
            file_path=sf.file_path,
            file_size=sf.file_size,
            chunk_hashes=sf.chunk_hashes,
        ))

    await log_event(
        db, tenant.id, "snapshot.synthesize_full", "BackupSnapshot", synth_snapshot.id,
        tenant.email,
        detail=f"Synthesized from snapshot {latest.id}: {len(file_records)} files, {len(all_hashes)} chunks",
    )
    await db.commit()
    await db.refresh(synth_snapshot)

    return SynthesizeResponse(
        synthetic_snapshot_id=synth_snapshot.id,
        source_id=source_id,
        merkle_root=merkle_root,
        total_size_bytes=synth_snapshot.total_size_bytes,
        chunk_count=synth_snapshot.chunk_count,
        file_count=len(file_records),
        created_at=synth_snapshot.created_at,
        message=(
            f"Synthetic full snapshot created from {len(file_records)} files "
            f"({len(all_hashes)} chunks) — no chain dependency"
        ),
    )
