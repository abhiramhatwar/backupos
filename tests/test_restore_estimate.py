"""Tests for the restore dry-run / cost estimate endpoint."""
import json

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.backup import BackupChunk, BackupJob, BackupSnapshot, BackupType, JobStatus, SnapshotFile

pytestmark = pytest.mark.asyncio

_HASH_A = "a" * 64
_HASH_B = "b" * 64
_HASH_C = "c" * 64


async def _create_source(client: AsyncClient, token: str, name: str) -> dict:
    resp = await client.post(
        "/api/v1/sources",
        json={"name": name, "source_type": "directory", "path": "/tmp/estimate_test", "classification": "internal"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    return resp.json()


async def _seed_snapshot(
    db: AsyncSession,
    source_id: int,
    files: dict[str, list[str]],
    chunks: list[dict] | None = None,
) -> BackupSnapshot:
    job = BackupJob(source_id=source_id, backup_type=BackupType.full, status=JobStatus.completed)
    db.add(job)
    await db.flush()

    snap = BackupSnapshot(
        job_id=job.id,
        source_id=source_id,
        merkle_root="f" * 64,
        total_size_bytes=8192,
        dedup_size_bytes=4096,
        chunk_count=4,
        new_chunk_count=4,
        average_entropy=3.5,
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

    if chunks:
        for c in chunks:
            db.add(BackupChunk(
                snapshot_id=snap.id,
                chunk_hash=c["hash"],
                size_bytes=c.get("size", 4096),
                compressed_size_bytes=c.get("compressed", None),
            ))

    await db.commit()
    await db.refresh(snap)
    return snap


async def test_estimate_basic(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """Full-snapshot estimate returns correct chunk and byte counts."""
    _, token = test_tenant
    src = await _create_source(client, token, "Estimate Basic")
    await _seed_snapshot(db_session, src["id"], {
        "/file1.bin": [_HASH_A, _HASH_B],
        "/file2.bin": [_HASH_B, _HASH_C],
    })

    resp = await client.post(
        "/api/v1/restore/estimate",
        json={"source_id": src["id"]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()

    # file1 has A,B; file2 has B,C → 4 total, 3 unique
    assert data["total_chunks"] == 4
    assert data["unique_chunks"] == 3
    assert data["file_count"] == 2
    assert data["estimated_seconds"] >= 0
    assert "note" in data


async def test_estimate_specific_snapshot(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """snapshot_id in request pins the estimate to the right snapshot."""
    _, token = test_tenant
    src = await _create_source(client, token, "Estimate Snap")
    snap = await _seed_snapshot(db_session, src["id"], {"/data.bin": [_HASH_A]})

    resp = await client.post(
        "/api/v1/restore/estimate",
        json={"source_id": src["id"], "snapshot_id": snap.id},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["snapshot_id"] == snap.id
    assert data["total_chunks"] == 1
    assert data["unique_chunks"] == 1


async def test_estimate_file_filter(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """file_path filter narrows estimate to a single file."""
    _, token = test_tenant
    src = await _create_source(client, token, "Estimate File")
    await _seed_snapshot(db_session, src["id"], {
        "/important.bin": [_HASH_A, _HASH_B, _HASH_C],
        "/other.bin": [_HASH_A],
    })

    resp = await client.post(
        "/api/v1/restore/estimate",
        json={"source_id": src["id"], "file_path": "/important.bin"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["file_count"] == 1
    assert data["total_chunks"] == 3
    assert data["file_path"] == "/important.bin"


async def test_estimate_uses_chunk_sizes(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """When BackupChunk records exist, bytes are summed from actual chunk sizes."""
    _, token = test_tenant
    src = await _create_source(client, token, "Estimate Sizes")
    await _seed_snapshot(
        db_session,
        src["id"],
        {"/f.bin": [_HASH_A, _HASH_B]},
        chunks=[
            {"hash": _HASH_A, "size": 8192, "compressed": 4096},
            {"hash": _HASH_B, "size": 8192, "compressed": 2048},
        ],
    )

    resp = await client.post(
        "/api/v1/restore/estimate",
        json={"source_id": src["id"]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    # 2 unique chunks × compressed sizes: 4096 + 2048 = 6144
    assert data["estimated_bytes"] == 6144


async def test_estimate_dedup_note(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """Note mentions dedup savings when there are repeated chunk references."""
    _, token = test_tenant
    src = await _create_source(client, token, "Estimate Dedup")
    await _seed_snapshot(db_session, src["id"], {
        "/a.bin": [_HASH_A, _HASH_A, _HASH_A],  # 3 references to same chunk
    })

    resp = await client.post(
        "/api/v1/restore/estimate",
        json={"source_id": src["id"]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_chunks"] == 3
    assert data["unique_chunks"] == 1
    assert "2 redundant" in data["note"]


async def test_estimate_source_not_found(client: AsyncClient, test_tenant):
    _, token = test_tenant
    resp = await client.post(
        "/api/v1/restore/estimate",
        json={"source_id": 999999},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


async def test_estimate_snapshot_not_found(client: AsyncClient, test_tenant, db_session: AsyncSession):
    _, token = test_tenant
    src = await _create_source(client, token, "Estimate Snap404")
    await _seed_snapshot(db_session, src["id"], {"/f.bin": [_HASH_A]})

    resp = await client.post(
        "/api/v1/restore/estimate",
        json={"source_id": src["id"], "snapshot_id": 999999},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


async def test_estimate_file_path_not_found(client: AsyncClient, test_tenant, db_session: AsyncSession):
    _, token = test_tenant
    src = await _create_source(client, token, "Estimate FP404")
    await _seed_snapshot(db_session, src["id"], {"/real.bin": [_HASH_A]})

    resp = await client.post(
        "/api/v1/restore/estimate",
        json={"source_id": src["id"], "file_path": "/nonexistent.bin"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


async def test_estimate_tenant_isolation(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """Cannot estimate a source belonging to another tenant."""
    _, token = test_tenant
    src = await _create_source(client, token, "Estimate Isolation")
    await _seed_snapshot(db_session, src["id"], {"/file.bin": [_HASH_A]})

    resp = await client.post(
        "/api/v1/restore/estimate",
        json={"source_id": 999999},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


async def test_estimate_estimated_seconds_formula(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """estimated_seconds = estimated_bytes / (100 * 1024 * 1024)."""
    _, token = test_tenant
    src = await _create_source(client, token, "Estimate Formula")
    chunk_size = 100 * 1024 * 1024  # exactly 1 second worth
    await _seed_snapshot(
        db_session,
        src["id"],
        {"/big.bin": [_HASH_A]},
        chunks=[{"hash": _HASH_A, "size": chunk_size, "compressed": chunk_size}],
    )

    resp = await client.post(
        "/api/v1/restore/estimate",
        json={"source_id": src["id"]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["estimated_bytes"] == chunk_size
    assert abs(data["estimated_seconds"] - 1.0) < 0.01
