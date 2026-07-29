"""
Tests for Tasks #23–28:
  #23 Synthetic Full Backup
  #24 Backup Catalog Search
  #25 Automated Recovery Verification (scheduler job)
  #26 WORM Immutable Snapshot Lock
  #27 Storage Analytics and Growth Projection
  #28 Cross-Snapshot File Version History
"""
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.backup import BackupJob, BackupSnapshot, BackupType, JobStatus, SnapshotFile
from app.models.source import DataSource

pytestmark = pytest.mark.asyncio

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _create_source(client: AsyncClient, token: str, name: str = "Feature Test Source") -> dict:
    resp = await client.post(
        "/api/v1/sources",
        json={"name": name, "source_type": "directory", "path": "/tmp/feat_test", "classification": "internal"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    return resp.json()


async def _seed_snapshot(
    db: AsyncSession,
    source_id: int,
    *,
    files: dict[str, list[str]] | None = None,
    dedup_size: int = 0,
    total_size: int = 1024,
    entropy: float = 4.5,
    parent_id: int | None = None,
) -> BackupSnapshot:
    """Insert a completed BackupJob + BackupSnapshot + optional SnapshotFile records."""
    job = BackupJob(
        source_id=source_id,
        backup_type=BackupType.full,
        status=JobStatus.completed,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    db.add(job)
    await db.flush()

    snapshot = BackupSnapshot(
        job_id=job.id,
        source_id=source_id,
        merkle_root="a" * 64,
        parent_snapshot_id=parent_id,
        total_size_bytes=total_size,
        dedup_size_bytes=dedup_size,
        chunk_count=len(files or {}),
        new_chunk_count=1,
        average_entropy=entropy,
    )
    db.add(snapshot)
    await db.flush()

    if files:
        for fpath, hashes in files.items():
            db.add(SnapshotFile(
                snapshot_id=snapshot.id,
                file_path=fpath,
                file_size=len(hashes) * 512,
                chunk_hashes=json.dumps(hashes),
            ))

    await db.commit()
    await db.refresh(snapshot)
    return snapshot


# ---------------------------------------------------------------------------
# Task #26 — WORM Immutable Snapshot Lock
# ---------------------------------------------------------------------------


async def test_lock_snapshot(client: AsyncClient, test_tenant, db_session: AsyncSession):
    tenant, token = test_tenant
    src = await _create_source(client, token, "WORM Source")
    snap = await _seed_snapshot(db_session, src["id"])

    resp = await client.post(
        f"/api/v1/snapshots/{snap.id}/lock",
        json={"lock_days": 30},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == snap.id
    assert data["locked_until"] is not None


async def test_unlock_snapshot(client: AsyncClient, test_tenant, db_session: AsyncSession):
    tenant, token = test_tenant
    src = await _create_source(client, token, "WORM Unlock Source")
    snap = await _seed_snapshot(db_session, src["id"])

    await client.post(
        f"/api/v1/snapshots/{snap.id}/lock",
        json={"lock_days": 7},
        headers={"Authorization": f"Bearer {token}"},
    )

    resp = await client.delete(
        f"/api/v1/snapshots/{snap.id}/lock",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["locked_until"] is None


async def test_get_snapshot(client: AsyncClient, test_tenant, db_session: AsyncSession):
    tenant, token = test_tenant
    src = await _create_source(client, token, "Get Snapshot Source")
    snap = await _seed_snapshot(db_session, src["id"])

    resp = await client.get(
        f"/api/v1/snapshots/{snap.id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["id"] == snap.id


async def test_snapshot_not_found(client: AsyncClient, test_tenant):
    _, token = test_tenant
    resp = await client.get(
        "/api/v1/snapshots/999999",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Task #23 — Synthetic Full Backup
# ---------------------------------------------------------------------------


async def test_synthesize_full_backup(client: AsyncClient, test_tenant, db_session: AsyncSession):
    tenant, token = test_tenant
    src = await _create_source(client, token, "Synthesize Source")
    hashes_a = ["a" * 64, "b" * 64]
    hashes_b = ["c" * 64]
    await _seed_snapshot(
        db_session,
        src["id"],
        files={
            "/data/file1.txt": hashes_a,
            "/data/file2.txt": hashes_b,
        },
        total_size=2048,
        dedup_size=512,
    )

    resp = await client.post(
        f"/api/v1/backups/{src['id']}/synthesize-full",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["source_id"] == src["id"]
    assert data["file_count"] == 2
    assert data["chunk_count"] == 3  # 2 + 1
    assert data["synthetic_snapshot_id"] != 0
    assert "no chain dependency" in data["message"]


async def test_synthesize_no_snapshots(client: AsyncClient, test_tenant):
    _, token = test_tenant
    src = await _create_source(client, token, "Empty Synth Source")
    resp = await client.post(
        f"/api/v1/backups/{src['id']}/synthesize-full",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Task #24 — Backup Catalog Search
# ---------------------------------------------------------------------------


async def test_catalog_search_glob(client: AsyncClient, test_tenant, db_session: AsyncSession):
    tenant, token = test_tenant
    src = await _create_source(client, token, "Catalog Source")
    await _seed_snapshot(
        db_session,
        src["id"],
        files={
            "/var/db/users.sql": ["a" * 64],
            "/var/db/orders.sql": ["b" * 64],
            "/var/log/access.log": ["c" * 64],
        },
    )

    resp = await client.get(
        f"/api/v1/sources/{src['id']}/catalog",
        params={"q": "*.sql"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    results = resp.json()
    paths = [r["file_path"] for r in results]
    assert "/var/db/users.sql" in paths
    assert "/var/db/orders.sql" in paths
    assert "/var/log/access.log" not in paths


async def test_catalog_search_no_match(client: AsyncClient, test_tenant, db_session: AsyncSession):
    tenant, token = test_tenant
    src = await _create_source(client, token, "Catalog No Match")
    await _seed_snapshot(
        db_session,
        src["id"],
        files={"/data/readme.txt": ["x" * 64]},
    )

    resp = await client.get(
        f"/api/v1/sources/{src['id']}/catalog",
        params={"q": "*.sql"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json() == []


async def test_catalog_search_no_snapshots(client: AsyncClient, test_tenant):
    _, token = test_tenant
    src = await _create_source(client, token, "Catalog Empty")
    resp = await client.get(
        f"/api/v1/sources/{src['id']}/catalog",
        params={"q": "*.sql"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Task #28 — Cross-Snapshot File Version History
# ---------------------------------------------------------------------------


async def test_file_version_history(client: AsyncClient, test_tenant, db_session: AsyncSession):
    tenant, token = test_tenant
    src = await _create_source(client, token, "History Source")
    FILE = "/etc/config.yml"

    snap1 = await _seed_snapshot(db_session, src["id"], files={FILE: ["aa" * 32]})
    snap2 = await _seed_snapshot(db_session, src["id"], files={FILE: ["bb" * 32]}, parent_id=snap1.id)
    snap3 = await _seed_snapshot(db_session, src["id"], files={FILE: ["bb" * 32]}, parent_id=snap2.id)

    resp = await client.get(
        f"/api/v1/sources/{src['id']}/files/{FILE}/history",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    versions = resp.json()
    assert len(versions) == 3

    # Newest first; snap1 entry is the first version (changed=True)
    # snap3 is newest and unchanged from snap2
    newest = versions[0]
    oldest = versions[-1]
    assert newest["snapshot_id"] == snap3.id
    assert newest["changed"] is False  # same hashes as snap2
    assert oldest["snapshot_id"] == snap1.id
    assert oldest["changed"] is True  # first version


async def test_file_version_history_missing_file(client: AsyncClient, test_tenant, db_session: AsyncSession):
    tenant, token = test_tenant
    src = await _create_source(client, token, "History Missing")
    await _seed_snapshot(db_session, src["id"], files={"/other/file.txt": ["cc" * 32]})

    resp = await client.get(
        f"/api/v1/sources/{src['id']}/files//nonexistent/file.txt/history",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json() == []


# ---------------------------------------------------------------------------
# Task #27 — Storage Analytics and Growth Projection
# ---------------------------------------------------------------------------


async def test_analytics_empty_source(client: AsyncClient, test_tenant):
    _, token = test_tenant
    src = await _create_source(client, token, "Analytics Empty")
    resp = await client.get(
        f"/api/v1/analytics/sources/{src['id']}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["snapshot_count"] == 0
    assert data["total_unique_bytes"] == 0
    assert data["growth_projection"] is None


async def test_analytics_with_snapshots(client: AsyncClient, test_tenant, db_session: AsyncSession):
    tenant, token = test_tenant
    src = await _create_source(client, token, "Analytics With Snaps")
    await _seed_snapshot(db_session, src["id"], total_size=1024, dedup_size=256)
    await _seed_snapshot(db_session, src["id"], total_size=2048, dedup_size=512)

    resp = await client.get(
        f"/api/v1/analytics/sources/{src['id']}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["snapshot_count"] == 2
    assert data["total_raw_bytes"] == 3072
    assert data["overall_dedup_ratio"] > 0
    assert len(data["trends"]) == 2
    # Two snapshots → growth projection is populated
    assert data["growth_projection"] is not None
    assert data["growth_projection"]["data_points"] == 2


async def test_analytics_source_not_found(client: AsyncClient, test_tenant):
    _, token = test_tenant
    resp = await client.get(
        "/api/v1/analytics/sources/999999",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Task #25 — Automated Recovery Verification (scheduler)
# ---------------------------------------------------------------------------


async def test_verify_snapshot_integrity_marks_passed(db_session: AsyncSession, test_tenant):
    """Scheduler job updates verification_status to 'passed' for a valid snapshot."""
    from app.core.merkle import MerkleTree
    from app.core.scheduler import verify_snapshot_integrity

    tenant, _ = test_tenant

    # Need a DataSource to satisfy the JOIN in the scheduler query
    source = DataSource(
        tenant_id=tenant.id,
        name="Verifier Source",
        source_type="directory",
        path="/tmp/verifier",
        classification="internal",
    )
    db_session.add(source)
    await db_session.flush()

    hashes = ["a" * 64, "b" * 64, "c" * 64]
    real_root = MerkleTree(hashes).root_hash

    job = BackupJob(
        source_id=source.id,
        backup_type=BackupType.full,
        status=JobStatus.completed,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    db_session.add(job)
    await db_session.flush()

    snap = BackupSnapshot(
        job_id=job.id,
        source_id=source.id,
        merkle_root=real_root,
        total_size_bytes=1024,
        dedup_size_bytes=256,
        chunk_count=3,
        new_chunk_count=3,
        average_entropy=4.5,
    )
    db_session.add(snap)
    await db_session.flush()

    for i, h in enumerate(hashes):
        db_session.add(SnapshotFile(
            snapshot_id=snap.id,
            file_path=f"/file{i}.bin",
            file_size=512,
            chunk_hashes=json.dumps([h]),
        ))

    await db_session.commit()

    # Patch the scheduler's session factory to use the test session
    from unittest.mock import AsyncMock, MagicMock
    import app.core.scheduler as sched_mod

    fake_factory = MagicMock()
    fake_cm = MagicMock()
    fake_cm.__aenter__ = AsyncMock(return_value=db_session)
    fake_cm.__aexit__ = AsyncMock(return_value=False)
    fake_factory.return_value = fake_cm
    sched_mod._sched_session_factory = fake_factory

    await verify_snapshot_integrity()

    await db_session.refresh(snap)
    assert snap.verification_status == "passed"
    assert snap.last_verified_at is not None


async def test_verify_snapshot_integrity_marks_failed(db_session: AsyncSession, test_tenant):
    """Scheduler job marks verification_status 'failed' when Merkle root is wrong."""
    from app.core.scheduler import verify_snapshot_integrity

    tenant, _ = test_tenant

    source = DataSource(
        tenant_id=tenant.id,
        name="Verifier Fail Source",
        source_type="directory",
        path="/tmp/verifier_fail",
        classification="internal",
    )
    db_session.add(source)
    await db_session.flush()

    job = BackupJob(
        source_id=source.id,
        backup_type=BackupType.full,
        status=JobStatus.completed,
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    db_session.add(job)
    await db_session.flush()

    snap = BackupSnapshot(
        job_id=job.id,
        source_id=source.id,
        merkle_root="0" * 64,  # deliberately wrong
        total_size_bytes=512,
        dedup_size_bytes=128,
        chunk_count=1,
        new_chunk_count=1,
        average_entropy=3.0,
    )
    db_session.add(snap)
    await db_session.flush()

    db_session.add(SnapshotFile(
        snapshot_id=snap.id,
        file_path="/tampered.bin",
        file_size=256,
        chunk_hashes=json.dumps(["d" * 64]),
    ))
    await db_session.commit()

    from unittest.mock import AsyncMock, MagicMock
    import app.core.scheduler as sched_mod

    fake_factory = MagicMock()
    fake_cm = MagicMock()
    fake_cm.__aenter__ = AsyncMock(return_value=db_session)
    fake_cm.__aexit__ = AsyncMock(return_value=False)
    fake_factory.return_value = fake_cm
    sched_mod._sched_session_factory = fake_factory

    await verify_snapshot_integrity()

    await db_session.refresh(snap)
    assert snap.verification_status == "failed"
