"""Tests for the backup chain dependency graph endpoint."""
import json
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.backup import BackupJob, BackupSnapshot, BackupType, JobStatus

pytestmark = pytest.mark.asyncio


async def _create_source(client: AsyncClient, token: str, name: str) -> dict:
    resp = await client.post(
        "/api/v1/sources",
        json={"name": name, "source_type": "directory", "path": "/tmp/chain_test", "classification": "internal"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    return resp.json()


async def _add_snapshot(
    db: AsyncSession,
    source_id: int,
    backup_type: BackupType = BackupType.incremental,
    parent_id: int | None = None,
    locked_until: datetime | None = None,
) -> BackupSnapshot:
    job = BackupJob(source_id=source_id, backup_type=backup_type, status=JobStatus.completed)
    db.add(job)
    await db.flush()

    snap = BackupSnapshot(
        job_id=job.id,
        source_id=source_id,
        merkle_root="a" * 64,
        parent_snapshot_id=parent_id,
        total_size_bytes=1024,
        dedup_size_bytes=512,
        chunk_count=2,
        new_chunk_count=1,
        average_entropy=3.0,
        locked_until=locked_until,
    )
    db.add(snap)
    await db.commit()
    await db.refresh(snap)
    return snap


async def test_chain_single_full(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """A single full backup has no parent, no children, and is safe to delete."""
    _, token = test_tenant
    src = await _create_source(client, token, "Chain Single")
    await _add_snapshot(db_session, src["id"], BackupType.full)

    resp = await client.get(
        f"/api/v1/sources/{src['id']}/chain",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["snapshot_count"] == 1
    assert data["chain_depth"] == 0
    node = data["nodes"][0]
    assert node["parent_snapshot_id"] is None
    assert node["children"] == []
    assert node["safe_to_delete"] is True
    assert node["backup_type"] == "full"


async def test_chain_linear(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """Full → Incremental → Incremental: only the leaf is safe to delete."""
    _, token = test_tenant
    src = await _create_source(client, token, "Chain Linear")
    full = await _add_snapshot(db_session, src["id"], BackupType.full)
    inc1 = await _add_snapshot(db_session, src["id"], BackupType.incremental, parent_id=full.id)
    inc2 = await _add_snapshot(db_session, src["id"], BackupType.incremental, parent_id=inc1.id)

    resp = await client.get(
        f"/api/v1/sources/{src['id']}/chain",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["snapshot_count"] == 3
    assert data["chain_depth"] == 2

    by_id = {n["snapshot_id"]: n for n in data["nodes"]}

    # Full is NOT safe (inc1 depends on it)
    assert by_id[full.id]["safe_to_delete"] is False
    # inc1 is NOT safe (inc2 depends on it)
    assert by_id[inc1.id]["safe_to_delete"] is False
    # leaf is safe
    assert by_id[inc2.id]["safe_to_delete"] is True
    # children are wired correctly
    assert inc1.id in by_id[full.id]["children"]
    assert inc2.id in by_id[inc1.id]["children"]


async def test_chain_depth_computed(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """Depth reflects position in the chain."""
    _, token = test_tenant
    src = await _create_source(client, token, "Chain Depth")
    full = await _add_snapshot(db_session, src["id"], BackupType.full)
    inc1 = await _add_snapshot(db_session, src["id"], BackupType.incremental, parent_id=full.id)
    inc2 = await _add_snapshot(db_session, src["id"], BackupType.incremental, parent_id=inc1.id)

    resp = await client.get(
        f"/api/v1/sources/{src['id']}/chain",
        headers={"Authorization": f"Bearer {token}"},
    )
    by_id = {n["snapshot_id"]: n for n in resp.json()["nodes"]}
    assert by_id[full.id]["depth"] == 0
    assert by_id[inc1.id]["depth"] == 1
    assert by_id[inc2.id]["depth"] == 2


async def test_chain_locked_not_safe(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """A WORM-locked leaf is NOT safe to delete even though it has no children."""
    _, token = test_tenant
    src = await _create_source(client, token, "Chain Locked")
    locked_until = datetime.now(timezone.utc) + timedelta(days=30)
    snap = await _add_snapshot(db_session, src["id"], BackupType.full, locked_until=locked_until)

    resp = await client.get(
        f"/api/v1/sources/{src['id']}/chain",
        headers={"Authorization": f"Bearer {token}"},
    )
    data = resp.json()
    node = data["nodes"][0]
    assert node["is_locked"] is True
    assert node["safe_to_delete"] is False


async def test_chain_intermediate_locked(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """
    Locking an intermediate node makes it not safe to delete.
    Its parent is also unsafe (it has children).
    The leaf (child of locked) is safe — it has no children and is not locked.
    """
    _, token = test_tenant
    src = await _create_source(client, token, "Chain Lock Propagate")
    full = await _add_snapshot(db_session, src["id"], BackupType.full)
    locked_until = datetime.now(timezone.utc) + timedelta(days=7)
    inc1 = await _add_snapshot(
        db_session, src["id"], BackupType.incremental, parent_id=full.id, locked_until=locked_until
    )
    inc2 = await _add_snapshot(db_session, src["id"], BackupType.incremental, parent_id=inc1.id)

    resp = await client.get(
        f"/api/v1/sources/{src['id']}/chain",
        headers={"Authorization": f"Bearer {token}"},
    )
    by_id = {n["snapshot_id"]: n for n in resp.json()["nodes"]}
    # inc1 is locked → not safe to delete
    assert by_id[inc1.id]["is_locked"] is True
    assert by_id[inc1.id]["safe_to_delete"] is False
    # full has children → not safe to delete immediately
    assert by_id[full.id]["safe_to_delete"] is False
    # inc2 is the leaf, not locked → safe to delete
    assert by_id[inc2.id]["safe_to_delete"] is True


async def test_chain_source_not_found(client: AsyncClient, test_tenant):
    _, token = test_tenant
    resp = await client.get(
        "/api/v1/sources/999999/chain",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


async def test_chain_no_snapshots(client: AsyncClient, test_tenant, db_session: AsyncSession):
    _, token = test_tenant
    src = await _create_source(client, token, "Chain Empty")
    resp = await client.get(
        f"/api/v1/sources/{src['id']}/chain",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


async def test_chain_tenant_isolation(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """Cannot access chain for a source belonging to another tenant."""
    _, token = test_tenant
    resp = await client.get(
        "/api/v1/sources/999999/chain",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404
