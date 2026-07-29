"""
Snapshot management — WORM immutable lock and direct snapshot lookup.

POST /api/v1/snapshots/{id}/lock
  Apply a Write-Once Read-Many lock for N days.  A locked snapshot is immune
  to retention pruning until the lock expires, regardless of policy settings.

DELETE /api/v1/snapshots/{id}/lock
  Remove the lock early (e.g., after a regulatory hold ends).

GET /api/v1/snapshots/{id}
  Retrieve snapshot metadata including lock state and verification status.
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_tenant
from app.core.database import get_db
from app.models.backup import BackupSnapshot
from app.models.source import DataSource
from app.models.tenant import Tenant
from app.schemas.backup import SnapshotResponse

router = APIRouter()


class LockRequest(BaseModel):
    lock_days: int = 30


async def _get_owned_snapshot(
    snapshot_id: int,
    tenant: Tenant,
    db: AsyncSession,
) -> BackupSnapshot:
    stmt = (
        select(BackupSnapshot)
        .join(DataSource, BackupSnapshot.source_id == DataSource.id)
        .where(BackupSnapshot.id == snapshot_id, DataSource.tenant_id == tenant.id)
    )
    snapshot = (await db.execute(stmt)).scalar_one_or_none()
    if not snapshot:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    return snapshot


@router.get("/{snapshot_id}", response_model=SnapshotResponse)
async def get_snapshot(
    snapshot_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    snapshot = await _get_owned_snapshot(snapshot_id, tenant, db)
    return SnapshotResponse.from_orm_with_ratio(snapshot)


@router.post("/{snapshot_id}/lock", response_model=SnapshotResponse, status_code=status.HTTP_200_OK)
async def lock_snapshot(
    snapshot_id: int,
    payload: LockRequest,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    """
    Apply a WORM immutable lock.  The snapshot cannot be deleted or pruned
    until lock_days have elapsed.  Re-locking extends the expiry.
    """
    snapshot = await _get_owned_snapshot(snapshot_id, tenant, db)
    snapshot.locked_until = datetime.now(timezone.utc) + timedelta(days=payload.lock_days)
    await db.commit()
    await db.refresh(snapshot)
    return SnapshotResponse.from_orm_with_ratio(snapshot)


@router.delete("/{snapshot_id}/lock", response_model=SnapshotResponse)
async def unlock_snapshot(
    snapshot_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    """Remove the WORM lock before its natural expiry."""
    snapshot = await _get_owned_snapshot(snapshot_id, tenant, db)
    snapshot.locked_until = None
    await db.commit()
    await db.refresh(snapshot)
    return SnapshotResponse.from_orm_with_ratio(snapshot)
