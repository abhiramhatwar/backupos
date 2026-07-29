"""
Virtual snapshot filesystem browser.

GET /api/v1/sources/{source_id}/snapshots/{snapshot_id}/browse?path=/
  Returns a directory listing of any backup snapshot as if it were a live
  filesystem — no actual restore needed.  The path parameter controls which
  directory level to inspect; omit it (or pass "/") for the root.

Response shape:
  {
    "path": "/var/www",
    "snapshot_id": 42,
    "entries": [
      {"name": "html",  "type": "directory", "size": 0,    "child_count": 5},
      {"name": "nginx.conf", "type": "file", "size": 4096, "child_count": 0,
       "chunk_count": 2, "full_path": "/var/www/nginx.conf"}
    ]
  }

Implementation note: SnapshotFile records store the absolute path of each
backed-up file.  The browser reconstructs the virtual directory tree entirely
in memory from those paths — no separate directory index is needed.
"""
import os
from typing import Literal

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


class BrowseEntry(BaseModel):
    name: str
    type: Literal["file", "directory"]
    size: int
    chunk_count: int
    child_count: int
    full_path: str


class BrowseResponse(BaseModel):
    path: str
    snapshot_id: int
    source_id: int
    total_entries: int
    entries: list[BrowseEntry]


def _normalise(path: str) -> str:
    """Ensure path starts with / and has no trailing slash (except root)."""
    path = "/" + path.strip("/")
    return path


def _build_listing(files: list[SnapshotFile], browse_path: str) -> list[BrowseEntry]:
    """
    Walk SnapshotFile records and produce a directory listing for browse_path.

    Direct child files are returned as "file" entries.
    Paths that descend into subdirectories are collapsed into a single
    "directory" entry with child_count = number of files underneath it.
    """
    browse_path = _normalise(browse_path)
    prefix = browse_path if browse_path == "/" else browse_path + "/"

    # Map: immediate child name → aggregated info
    dirs: dict[str, int] = {}      # name → child file count
    file_entries: list[BrowseEntry] = []

    for sf in files:
        fp = sf.file_path
        if not fp.startswith(prefix):
            continue

        relative = fp[len(prefix):]
        if not relative:
            continue

        slash_pos = relative.find("/")
        if slash_pos == -1:
            # Direct file child
            file_entries.append(BrowseEntry(
                name=relative,
                type="file",
                size=sf.file_size,
                chunk_count=len(sf.get_chunk_hashes()),
                child_count=0,
                full_path=fp,
            ))
        else:
            # Lives inside a subdirectory
            dir_name = relative[:slash_pos]
            dirs[dir_name] = dirs.get(dir_name, 0) + 1

    dir_entries = [
        BrowseEntry(
            name=name,
            type="directory",
            size=0,
            chunk_count=0,
            child_count=count,
            full_path=_normalise(prefix + name),
        )
        for name, count in sorted(dirs.items())
    ]

    file_entries.sort(key=lambda e: e.name)
    return dir_entries + file_entries


@router.get(
    "/{source_id}/snapshots/{snapshot_id}/browse",
    response_model=BrowseResponse,
)
async def browse_snapshot(
    source_id: int,
    snapshot_id: int,
    path: str = Query("/", description="Directory path to list (e.g. /var/www)"),
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    """
    Browse a backup snapshot as a virtual filesystem.

    No restore is performed — the directory tree is reconstructed entirely
    from SnapshotFile metadata stored at backup time.
    """
    source_result = await db.execute(
        select(DataSource).where(
            DataSource.id == source_id,
            DataSource.tenant_id == tenant.id,
        )
    )
    if not source_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Data source not found")

    snap_result = await db.execute(
        select(BackupSnapshot).where(
            BackupSnapshot.id == snapshot_id,
            BackupSnapshot.source_id == source_id,
        )
    )
    if not snap_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Snapshot not found")

    files_result = await db.execute(
        select(SnapshotFile).where(SnapshotFile.snapshot_id == snapshot_id)
    )
    all_files = files_result.scalars().all()

    if not all_files:
        raise HTTPException(
            status_code=404,
            detail="Snapshot has no file records — cannot browse",
        )

    entries = _build_listing(all_files, path)
    browse_path = _normalise(path)

    return BrowseResponse(
        path=browse_path,
        snapshot_id=snapshot_id,
        source_id=source_id,
        total_entries=len(entries),
        entries=entries,
    )
