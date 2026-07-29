import os

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_tenant
from app.core.config import settings
from app.core.database import get_db
from app.core.merkle import MerkleTree
from app.models.backup import BackupChunk, BackupJob, BackupSnapshot, JobStatus, SnapshotFile
from app.models.restore_job import RestoreJob
from app.models.source import DataSource
from app.models.tenant import Tenant

router = APIRouter()


class RestoreRequest(BaseModel):
    source_id: int
    snapshot_id: int | None = None
    restore_path: str | None = None
    file_path: str | None = None


class RestoreJobResponse(BaseModel):
    id: int
    source_id: int
    snapshot_id: int | None
    celery_task_id: str | None
    restore_path: str
    status: str
    error_message: str | None
    started_at: object | None
    completed_at: object | None
    created_at: object

    model_config = {"from_attributes": True}


class VerifyResponse(BaseModel):
    snapshot_id: int
    source_id: int
    chunk_count: int
    merkle_root_stored: str
    merkle_root_computed: str
    is_valid: bool


@router.post("", response_model=RestoreJobResponse, status_code=status.HTTP_201_CREATED)
async def trigger_restore(
    payload: RestoreRequest,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a restore job.  Defaults to the latest snapshot for the source."""
    source_result = await db.execute(
        select(DataSource).where(
            DataSource.id == payload.source_id,
            DataSource.tenant_id == tenant.id,
        )
    )
    source = source_result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Data source not found")

    if payload.snapshot_id:
        snapshot_result = await db.execute(
            select(BackupSnapshot).where(
                BackupSnapshot.id == payload.snapshot_id,
                BackupSnapshot.source_id == payload.source_id,
            )
        )
        snapshot = snapshot_result.scalar_one_or_none()
        if not snapshot:
            raise HTTPException(status_code=404, detail="Snapshot not found")
        snapshot_id = snapshot.id
    else:
        latest_stmt = (
            select(BackupSnapshot)
            .where(BackupSnapshot.source_id == payload.source_id)
            .order_by(BackupSnapshot.created_at.desc())
            .limit(1)
        )
        latest = (await db.execute(latest_stmt)).scalar_one_or_none()
        if not latest:
            raise HTTPException(status_code=404, detail="No snapshots found for this source")
        snapshot_id = latest.id

    restore_path = payload.restore_path or os.path.join(
        settings.cas_store_path, "restores", f"source_{payload.source_id}_snap_{snapshot_id}"
    )

    job = RestoreJob(
        source_id=payload.source_id,
        snapshot_id=snapshot_id,
        restore_path=restore_path,
        status=JobStatus.pending,
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    try:
        from app.workers.restore_worker import run_restore

        task = run_restore.delay(job.id, snapshot_id, restore_path, payload.file_path)
        job.celery_task_id = task.id
        await db.commit()
        await db.refresh(job)
    except Exception:
        job.status = JobStatus.failed
        job.error_message = "Failed to dispatch restore task (broker unavailable)"
        await db.commit()
        await db.refresh(job)

    return job


@router.get("/{job_id}", response_model=RestoreJobResponse)
async def get_restore_job(
    job_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    stmt = (
        select(RestoreJob)
        .join(DataSource, RestoreJob.source_id == DataSource.id)
        .where(RestoreJob.id == job_id, DataSource.tenant_id == tenant.id)
    )
    result = await db.execute(stmt)
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Restore job not found")
    return job


@router.get("/{source_id}/verify/{snapshot_id}", response_model=VerifyResponse)
async def verify_snapshot(
    source_id: int,
    snapshot_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    """
    Verify snapshot integrity by recomputing the Merkle root and comparing to the
    stored root.

    Uses SnapshotFile records (complete per-file chunk manifests) as the primary
    source of truth.  This is correct even for incremental backups where only new
    chunks are written to BackupChunk.  Falls back to BackupChunk records when no
    SnapshotFile records exist (legacy snapshots).
    """
    source_result = await db.execute(
        select(DataSource).where(
            DataSource.id == source_id,
            DataSource.tenant_id == tenant.id,
        )
    )
    if not source_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Data source not found")

    snapshot_result = await db.execute(
        select(BackupSnapshot).where(
            BackupSnapshot.id == snapshot_id,
            BackupSnapshot.source_id == source_id,
        )
    )
    snapshot = snapshot_result.scalar_one_or_none()
    if not snapshot:
        raise HTTPException(status_code=404, detail="Snapshot not found")

    # Primary: reconstruct full chunk list from SnapshotFile manifests
    sf_result = await db.execute(
        select(SnapshotFile)
        .where(SnapshotFile.snapshot_id == snapshot_id)
        .order_by(SnapshotFile.id)
    )
    sf_records = sf_result.scalars().all()

    if sf_records:
        chunk_hashes = []
        for sf in sf_records:
            chunk_hashes.extend(sf.get_chunk_hashes())
    else:
        # Legacy fallback: use BackupChunk records
        chunks_result = await db.execute(
            select(BackupChunk)
            .where(BackupChunk.snapshot_id == snapshot_id)
            .order_by(BackupChunk.id)
        )
        chunk_hashes = [c.chunk_hash for c in chunks_result.scalars().all()]

    computed_root = MerkleTree(chunk_hashes).root_hash
    is_valid = computed_root == snapshot.merkle_root

    return VerifyResponse(
        snapshot_id=snapshot_id,
        source_id=source_id,
        chunk_count=len(chunk_hashes),
        merkle_root_stored=snapshot.merkle_root,
        merkle_root_computed=computed_root,
        is_valid=is_valid,
    )
