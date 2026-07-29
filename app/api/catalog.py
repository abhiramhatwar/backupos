"""
Backup catalog search and cross-snapshot file version history.

GET /api/v1/sources/{source_id}/catalog?q=<glob>
  Search for files matching a glob pattern within the latest (or specified)
  snapshot.  Uses fnmatch so patterns like *.sql, /var/**/*.log, and
  /etc/nginx/* all work as expected.

GET /api/v1/sources/{source_id}/files/{path:path}/history
  Return every version of a specific file path across all snapshots, newest
  first.  Each entry carries a `changed` flag that is True when the file's
  chunk hashes differ from the previous (older) version — this lets operators
  instantly see which backups contain a modified version of a critical file.
"""
import fnmatch
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_tenant
from app.core.database import get_db
from app.models.backup import BackupSnapshot, SnapshotFile
from app.models.source import DataSource
from app.models.tenant import Tenant

router = APIRouter()


class CatalogEntry(BaseModel):
    file_path: str
    file_size: int
    chunk_count: int
    snapshot_id: int
    snapshot_created_at: object


class FileVersion(BaseModel):
    snapshot_id: int
    snapshot_created_at: object
    file_size: int
    chunk_count: int
    changed: bool


async def _verify_source_ownership(source_id: int, tenant: Tenant, db: AsyncSession) -> None:
    result = await db.execute(
        select(DataSource).where(
            DataSource.id == source_id,
            DataSource.tenant_id == tenant.id,
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Data source not found")


@router.get("/{source_id}/catalog", response_model=list[CatalogEntry])
async def search_catalog(
    source_id: int,
    q: str = Query(..., description="Glob pattern, e.g. *.sql or /var/data/*.log"),
    snapshot_id: Optional[int] = Query(None, description="Target snapshot; defaults to latest"),
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    await _verify_source_ownership(source_id, tenant, db)

    if snapshot_id is not None:
        snap_result = await db.execute(
            select(BackupSnapshot).where(
                BackupSnapshot.id == snapshot_id,
                BackupSnapshot.source_id == source_id,
            )
        )
        snap = snap_result.scalar_one_or_none()
        if not snap:
            raise HTTPException(status_code=404, detail="Snapshot not found")
    else:
        latest_stmt = (
            select(BackupSnapshot)
            .where(BackupSnapshot.source_id == source_id)
            .order_by(BackupSnapshot.created_at.desc())
            .limit(1)
        )
        snap = (await db.execute(latest_stmt)).scalar_one_or_none()
        if not snap:
            raise HTTPException(status_code=404, detail="No snapshots found for this source")

    files_result = await db.execute(
        select(SnapshotFile).where(SnapshotFile.snapshot_id == snap.id)
    )
    all_files = files_result.scalars().all()

    matches = [f for f in all_files if fnmatch.fnmatch(f.file_path, q)]

    return [
        CatalogEntry(
            file_path=f.file_path,
            file_size=f.file_size,
            chunk_count=len(f.get_chunk_hashes()),
            snapshot_id=snap.id,
            snapshot_created_at=snap.created_at,
        )
        for f in matches
    ]


@router.get("/{source_id}/files/{path:path}/history", response_model=list[FileVersion])
async def file_version_history(
    source_id: int,
    path: str,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
):
    """Return all backup versions of a specific file, newest first."""
    await _verify_source_ownership(source_id, tenant, db)

    snaps_result = await db.execute(
        select(BackupSnapshot)
        .where(BackupSnapshot.source_id == source_id)
        .order_by(BackupSnapshot.created_at.desc())
        .limit(limit)
    )
    snapshots = snaps_result.scalars().all()
    if not snapshots:
        return []

    snap_ids = [s.id for s in snapshots]
    snap_map = {s.id: s for s in snapshots}

    files_result = await db.execute(
        select(SnapshotFile).where(
            SnapshotFile.snapshot_id.in_(snap_ids),
            SnapshotFile.file_path == path,
        )
    )
    file_map = {sf.snapshot_id: sf for sf in files_result.scalars().all()}

    # Walk oldest→newest to compute change flags, then reverse for response
    ordered_ids = list(reversed(snap_ids))
    entries = []
    prev_hashes = None
    for snap_id in ordered_ids:
        if snap_id not in file_map:
            prev_hashes = None
            continue
        sf = file_map[snap_id]
        hashes = sf.get_chunk_hashes()
        changed = prev_hashes is None or hashes != prev_hashes
        entries.append((snap_id, hashes, changed, sf.file_size))
        prev_hashes = hashes

    return [
        FileVersion(
            snapshot_id=snap_id,
            snapshot_created_at=snap_map[snap_id].created_at,
            file_size=file_size,
            chunk_count=len(hashes),
            changed=changed,
        )
        for snap_id, hashes, changed, file_size in reversed(entries)
    ]
