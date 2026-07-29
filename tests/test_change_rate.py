"""Tests for the pre-backup change rate sampling endpoint."""
import json

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.backup import BackupJob, BackupSnapshot, BackupType, JobStatus, SnapshotFile

pytestmark = pytest.mark.asyncio

_H_A = "a" * 64
_H_B = "b" * 64
_H_C = "c" * 64
_H_D = "d" * 64


async def _create_source(client: AsyncClient, token: str, name: str) -> dict:
    resp = await client.post(
        "/api/v1/sources",
        json={"name": name, "source_type": "directory", "path": "/tmp/cr_test", "classification": "internal"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    return resp.json()


async def _add_snapshot(
    db: AsyncSession,
    source_id: int,
    files: dict[str, list[str]],
) -> BackupSnapshot:
    job = BackupJob(source_id=source_id, backup_type=BackupType.full, status=JobStatus.completed)
    db.add(job)
    await db.flush()

    snap = BackupSnapshot(
        job_id=job.id,
        source_id=source_id,
        merkle_root="e" * 64,
        total_size_bytes=2048,
        dedup_size_bytes=1024,
        chunk_count=sum(len(v) for v in files.values()),
        new_chunk_count=1,
        average_entropy=3.2,
    )
    db.add(snap)
    await db.flush()

    for path, hashes in files.items():
        db.add(SnapshotFile(
            snapshot_id=snap.id,
            file_path=path,
            file_size=len(hashes) * 512,
            chunk_hashes=json.dumps(hashes),
        ))

    await db.commit()
    await db.refresh(snap)
    return snap


async def test_no_change(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """Identical chunk sets across two snapshots → should_backup=False."""
    _, token = test_tenant
    src = await _create_source(client, token, "CR No Change")
    # Both snapshots have exactly the same chunks
    await _add_snapshot(db_session, src["id"], {"/file.bin": [_H_A, _H_B]})
    await _add_snapshot(db_session, src["id"], {"/file.bin": [_H_A, _H_B]})

    resp = await client.post(
        f"/api/v1/backups/{src['id']}/sample-change-rate",
        params={"change_threshold": "0.01"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["estimated_change_rate"] == 0.0
    assert data["should_backup"] is False
    assert data["changed_chunks"] == 0


async def test_full_change(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """Completely different chunk sets → should_backup=True."""
    _, token = test_tenant
    src = await _create_source(client, token, "CR Full Change")
    await _add_snapshot(db_session, src["id"], {"/file.bin": [_H_A, _H_B]})
    await _add_snapshot(db_session, src["id"], {"/file.bin": [_H_C, _H_D]})

    resp = await client.post(
        f"/api/v1/backups/{src['id']}/sample-change-rate",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["estimated_change_rate"] == 1.0
    assert data["should_backup"] is True
    assert data["changed_chunks"] == data["sample_size"]


async def test_partial_change(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """50% of chunks changed → above 1% threshold → should_backup=True."""
    _, token = test_tenant
    src = await _create_source(client, token, "CR Partial")
    await _add_snapshot(db_session, src["id"], {"/file.bin": [_H_A, _H_B]})
    # Second snapshot shares _H_A but has new _H_C instead of _H_B
    await _add_snapshot(db_session, src["id"], {"/file.bin": [_H_A, _H_C]})

    resp = await client.post(
        f"/api/v1/backups/{src['id']}/sample-change-rate",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert 0.0 < data["estimated_change_rate"] <= 1.0
    assert data["should_backup"] is True


async def test_single_snapshot_always_backup(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """With only one snapshot (no baseline), should_backup is always True."""
    _, token = test_tenant
    src = await _create_source(client, token, "CR Single Snap")
    snap = await _add_snapshot(db_session, src["id"], {"/file.bin": [_H_A]})

    resp = await client.post(
        f"/api/v1/backups/{src['id']}/sample-change-rate",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["should_backup"] is True
    assert data["previous_snapshot_id"] is None
    assert data["latest_snapshot_id"] == snap.id


async def test_custom_threshold_zero(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """With threshold=0.0, any change rate triggers should_backup=True."""
    _, token = test_tenant
    src = await _create_source(client, token, "CR Threshold Zero")
    await _add_snapshot(db_session, src["id"], {"/file.bin": [_H_A, _H_B]})
    await _add_snapshot(db_session, src["id"], {"/file.bin": [_H_A, _H_B]})

    resp = await client.post(
        f"/api/v1/backups/{src['id']}/sample-change-rate",
        params={"change_threshold": "0.0"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    # 0.0 rate >= 0.0 threshold → True
    assert resp.json()["should_backup"] is True


async def test_snapshot_ids_in_response(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """Response carries the correct latest and previous snapshot IDs."""
    _, token = test_tenant
    src = await _create_source(client, token, "CR Snap IDs")
    snap1 = await _add_snapshot(db_session, src["id"], {"/a.bin": [_H_A]})
    snap2 = await _add_snapshot(db_session, src["id"], {"/a.bin": [_H_B]})

    resp = await client.post(
        f"/api/v1/backups/{src['id']}/sample-change-rate",
        headers={"Authorization": f"Bearer {token}"},
    )
    data = resp.json()
    assert data["latest_snapshot_id"] == snap2.id
    assert data["previous_snapshot_id"] == snap1.id


async def test_source_not_found(client: AsyncClient, test_tenant):
    _, token = test_tenant
    resp = await client.post(
        "/api/v1/backups/999999/sample-change-rate",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


async def test_no_snapshots(client: AsyncClient, test_tenant, db_session: AsyncSession):
    _, token = test_tenant
    src = await _create_source(client, token, "CR No Snaps")
    resp = await client.post(
        f"/api/v1/backups/{src['id']}/sample-change-rate",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404
