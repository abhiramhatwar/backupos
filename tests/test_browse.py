"""Tests for virtual snapshot filesystem browser."""
import json

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.backup import BackupJob, BackupSnapshot, BackupType, JobStatus, SnapshotFile
from app.api.browse import _build_listing, _normalise

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Unit tests for the tree-building logic (no HTTP needed)
# ---------------------------------------------------------------------------


class _FakeSF:
    """Minimal SnapshotFile stand-in for unit-testing the tree builder."""
    def __init__(self, path: str, size: int = 1024, hashes: list | None = None):
        self.file_path = path
        self.file_size = size
        self.chunk_hashes = json.dumps(hashes or ["a" * 64])

    def get_chunk_hashes(self) -> list[str]:
        return json.loads(self.chunk_hashes)


def _make_sf(path: str, size: int = 1024, hashes: list | None = None) -> "_FakeSF":
    return _FakeSF(path, size, hashes)


def test_normalise_root():
    assert _normalise("/") == "/"


def test_normalise_strips_trailing_slash():
    assert _normalise("/var/www/") == "/var/www"


def test_normalise_adds_leading_slash():
    assert _normalise("var/www") == "/var/www"


def test_build_listing_root():
    files = [
        _make_sf("/etc/hosts"),
        _make_sf("/etc/nginx/nginx.conf"),
        _make_sf("/var/log/app.log"),
    ]
    entries = _build_listing(files, "/")
    names = {e.name for e in entries}
    types = {e.name: e.type for e in entries}

    assert "etc" in names
    assert "var" in names
    assert types["etc"] == "directory"
    assert types["var"] == "directory"


def test_build_listing_subdir():
    files = [
        _make_sf("/etc/hosts", size=512),
        _make_sf("/etc/nginx/nginx.conf"),
        _make_sf("/etc/nginx/conf.d/default.conf"),
        _make_sf("/var/log/app.log"),
    ]
    entries = _build_listing(files, "/etc")
    names = {e.name for e in entries}
    types = {e.name: e.type for e in entries}

    assert "hosts" in names
    assert "nginx" in names
    assert "app.log" not in names
    assert types["hosts"] == "file"
    assert types["nginx"] == "directory"

    nginx_entry = next(e for e in entries if e.name == "nginx")
    assert nginx_entry.child_count == 2


def test_build_listing_file_size_preserved():
    files = [_make_sf("/data/big.bin", size=8192, hashes=["a" * 64, "b" * 64])]
    entries = _build_listing(files, "/data")
    assert len(entries) == 1
    assert entries[0].size == 8192
    assert entries[0].chunk_count == 2


def test_build_listing_empty_path():
    """Path that matches nothing returns empty list."""
    files = [_make_sf("/etc/hosts")]
    entries = _build_listing(files, "/nonexistent")
    assert entries == []


# ---------------------------------------------------------------------------
# Integration tests via HTTP client
# ---------------------------------------------------------------------------


async def _seed(db: AsyncSession, source_id: int, files: dict[str, list[str]]) -> BackupSnapshot:
    job = BackupJob(
        source_id=source_id,
        backup_type=BackupType.full,
        status=JobStatus.completed,
    )
    db.add(job)
    await db.flush()

    snap = BackupSnapshot(
        job_id=job.id,
        source_id=source_id,
        merkle_root="a" * 64,
        total_size_bytes=4096,
        dedup_size_bytes=1024,
        chunk_count=len(files),
        new_chunk_count=len(files),
        average_entropy=4.0,
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


async def _create_source(client: AsyncClient, token: str, name: str) -> dict:
    resp = await client.post(
        "/api/v1/sources",
        json={"name": name, "source_type": "directory", "path": "/tmp/browse_test", "classification": "internal"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    return resp.json()


async def test_browse_root(client: AsyncClient, test_tenant, db_session: AsyncSession):
    _, token = test_tenant
    src = await _create_source(client, token, "Browse Root")
    snap = await _seed(db_session, src["id"], {
        "/etc/hosts": ["a" * 64],
        "/etc/nginx/nginx.conf": ["b" * 64],
        "/var/log/app.log": ["c" * 64],
    })

    resp = await client.get(
        f"/api/v1/sources/{src['id']}/snapshots/{snap.id}/browse",
        params={"path": "/"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["path"] == "/"
    names = {e["name"] for e in data["entries"]}
    assert "etc" in names
    assert "var" in names
    assert all(e["type"] == "directory" for e in data["entries"])


async def test_browse_subdir(client: AsyncClient, test_tenant, db_session: AsyncSession):
    _, token = test_tenant
    src = await _create_source(client, token, "Browse Subdir")
    snap = await _seed(db_session, src["id"], {
        "/app/config.yml": ["a" * 64],
        "/app/main.py": ["b" * 64],
        "/app/lib/utils.py": ["c" * 64],
    })

    resp = await client.get(
        f"/api/v1/sources/{src['id']}/snapshots/{snap.id}/browse",
        params={"path": "/app"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["path"] == "/app"
    types = {e["name"]: e["type"] for e in data["entries"]}
    assert types["lib"] == "directory"
    assert types["config.yml"] == "file"
    assert types["main.py"] == "file"


async def test_browse_directory_child_count(client: AsyncClient, test_tenant, db_session: AsyncSession):
    _, token = test_tenant
    src = await _create_source(client, token, "Browse Child Count")
    snap = await _seed(db_session, src["id"], {
        "/data/a.bin": ["a" * 64],
        "/data/b.bin": ["b" * 64],
        "/data/c.bin": ["c" * 64],
    })

    resp = await client.get(
        f"/api/v1/sources/{src['id']}/snapshots/{snap.id}/browse",
        params={"path": "/"},
        headers={"Authorization": f"Bearer {token}"},
    )
    data = resp.json()
    data_entry = next(e for e in data["entries"] if e["name"] == "data")
    assert data_entry["child_count"] == 3


async def test_browse_snapshot_not_found(client: AsyncClient, test_tenant):
    _, token = test_tenant
    src = await _create_source(client, token, "Browse 404")
    resp = await client.get(
        f"/api/v1/sources/{src['id']}/snapshots/999999/browse",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


async def test_browse_tenant_isolation(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """Cannot browse a snapshot belonging to another source."""
    _, token = test_tenant
    src = await _create_source(client, token, "Browse Isolation")
    snap = await _seed(db_session, src["id"], {"/file.txt": ["a" * 64]})

    # Use a wrong source_id with the real snap id — should 404
    resp = await client.get(
        f"/api/v1/sources/999999/snapshots/{snap.id}/browse",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404
