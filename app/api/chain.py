"""
Backup chain dependency graph.

GET /api/v1/sources/{source_id}/chain
  Returns the full DAG of backup snapshots linked by parent_snapshot_id.
  Each node carries metadata about the snapshot and a safe-to-delete flag
  that tells operators whether removing the snapshot would orphan any
  dependent incremental backups downstream.

  Safe-to-delete = True when:
    • The snapshot has no child snapshots currently in the system (nothing
      depends on it for incremental restore), AND
    • The snapshot is not WORM-locked (locked_until is in the future).

Response shape:
  {
    "source_id": 1,
    "snapshot_count": 5,
    "chain_depth": 4,
    "nodes": [
      {
        "snapshot_id": 1,
        "parent_snapshot_id": null,
        "backup_type": "full",
        "created_at": "...",
        "total_size_bytes": 1000000,
        "chunk_count": 200,
        "merkle_root": "abc...",
        "is_locked": false,
        "children": [2, 3],
        "safe_to_delete": false
      },
      ...
    ]
  }
"""
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_tenant
from app.core.database import get_db
from app.models.backup import BackupJob, BackupSnapshot
from app.models.source import DataSource
from app.models.tenant import Tenant

router = APIRouter()


class ChainNode(BaseModel):
    snapshot_id: int
    parent_snapshot_id: Optional[int]
    backup_type: str
    created_at: datetime
    total_size_bytes: int
    chunk_count: int
    merkle_root: str
    is_locked: bool
    children: list[int]
    safe_to_delete: bool
    depth: int


class ChainResponse(BaseModel):
    source_id: int
    snapshot_count: int
    chain_depth: int
    nodes: list[ChainNode]


def _build_chain(snapshots: list[BackupSnapshot], backup_type_map: dict[int, str] | None = None) -> list[ChainNode]:
    """
    Walk the parent_snapshot_id DAG and annotate every node with:
      - children: list of direct child snapshot IDs
      - depth: distance from the nearest root (full backup with no parent)
      - safe_to_delete: True only when the node has no locked or
        dependency-carrying descendants
    """
    now = datetime.now(timezone.utc)

    id_map: dict[int, BackupSnapshot] = {s.id: s for s in snapshots}
    children_map: dict[int, list[int]] = {s.id: [] for s in snapshots}

    for snap in snapshots:
        if snap.parent_snapshot_id and snap.parent_snapshot_id in children_map:
            children_map[snap.parent_snapshot_id].append(snap.id)

    # Compute depth via BFS from roots
    depth_map: dict[int, int] = {}
    roots = [s.id for s in snapshots if not s.parent_snapshot_id]
    queue = [(rid, 0) for rid in roots]
    while queue:
        sid, d = queue.pop(0)
        depth_map[sid] = d
        for child_id in children_map[sid]:
            queue.append((child_id, d + 1))
    # Any snapshot whose parent is outside the result set gets depth 0
    for snap in snapshots:
        if snap.id not in depth_map:
            depth_map[snap.id] = 0

    # Compute safe_to_delete bottom-up (topological order: leaves first)
    safe_map: dict[int, bool] = {}

    def _is_locked(snap: BackupSnapshot) -> bool:
        if not snap.locked_until:
            return False
        lu = snap.locked_until
        if lu.tzinfo is None:
            lu = lu.replace(tzinfo=timezone.utc)
        return lu > now

    for sid, snap in id_map.items():
        # Safe to delete right now: not locked AND no snapshot currently depends on it
        safe_map[sid] = not _is_locked(snap) and len(children_map[sid]) == 0

    nodes = []
    for snap in sorted(snapshots, key=lambda s: s.created_at):
        nodes.append(ChainNode(
            snapshot_id=snap.id,
            parent_snapshot_id=snap.parent_snapshot_id,
            backup_type=(backup_type_map or {}).get(snap.id, "unknown"),
            created_at=snap.created_at,
            total_size_bytes=snap.total_size_bytes,
            chunk_count=snap.chunk_count,
            merkle_root=snap.merkle_root,
            is_locked=_is_locked(snap),
            children=sorted(children_map[snap.id]),
            safe_to_delete=safe_map.get(snap.id, True),
            depth=depth_map.get(snap.id, 0),
        ))

    return nodes


@router.get("/{source_id}/chain", response_model=ChainResponse)
async def get_backup_chain(
    source_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    """
    Return the full backup chain DAG for a data source.

    Each node is annotated with its children and a safe-to-delete flag.
    A node is safe to delete when:
      1. It has no children that are incrementals depending on it, OR
         all of its descendants are themselves safe to delete.
      2. It is not WORM-locked.

    A node is safe to delete immediately when nothing currently depends on it
    (it has no child snapshots) and it is not WORM-locked.  Use this before
    pruning to understand which snapshots can be removed without breaking
    restore chains.
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
        select(BackupSnapshot, BackupJob.backup_type)
        .join(BackupJob, BackupSnapshot.job_id == BackupJob.id)
        .where(BackupSnapshot.source_id == source_id)
        .order_by(BackupSnapshot.created_at.asc())
    )
    rows = snap_result.all()
    snapshots = [r[0] for r in rows]
    backup_type_map: dict[int, str] = {r[0].id: r[1].value for r in rows}

    if not snapshots:
        raise HTTPException(status_code=404, detail="No snapshots found for this source")

    nodes = _build_chain(list(snapshots), backup_type_map)
    chain_depth = max((n.depth for n in nodes), default=0)

    return ChainResponse(
        source_id=source_id,
        snapshot_count=len(nodes),
        chain_depth=chain_depth,
        nodes=nodes,
    )
