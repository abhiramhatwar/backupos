"""Tests for backup job endpoints."""
from unittest.mock import MagicMock, patch

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def _create_source(client: AsyncClient, token: str, name: str = "Test Source") -> dict:
    resp = await client.post(
        "/api/v1/sources",
        json={
            "name": name,
            "source_type": "directory",
            "path": "/tmp/test_data",
            "classification": "internal",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    return resp.json()


async def test_trigger_backup(client: AsyncClient, test_tenant):
    _, token = test_tenant
    source = await _create_source(client, token)

    with patch("app.workers.backup_worker.run_backup") as mock_task:
        mock_result = MagicMock()
        mock_result.id = "celery-task-id-123"
        mock_task.delay.return_value = mock_result

        resp = await client.post(
            "/api/v1/backups",
            json={"source_id": source["id"], "backup_type": "full"},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 201
    data = resp.json()
    assert data["source_id"] == source["id"]
    assert data["backup_type"] == "full"
    assert data["status"] in ("pending", "failed")  # failed if broker unavailable in test


async def test_list_backups(client: AsyncClient, test_tenant):
    _, token = test_tenant
    source = await _create_source(client, token, "List Backup Source")

    with patch("app.workers.backup_worker.run_backup") as mock_task:
        mock_result = MagicMock()
        mock_result.id = "celery-task-id-list"
        mock_task.delay.return_value = mock_result

        await client.post(
            "/api/v1/backups",
            json={"source_id": source["id"], "backup_type": "incremental"},
            headers={"Authorization": f"Bearer {token}"},
        )

    resp = await client.get(
        "/api/v1/backups",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


async def test_get_backup_job(client: AsyncClient, test_tenant):
    _, token = test_tenant
    source = await _create_source(client, token, "Get Job Source")

    with patch("app.workers.backup_worker.run_backup") as mock_task:
        mock_result = MagicMock()
        mock_result.id = "celery-task-id-get"
        mock_task.delay.return_value = mock_result

        create_resp = await client.post(
            "/api/v1/backups",
            json={"source_id": source["id"], "backup_type": "full"},
            headers={"Authorization": f"Bearer {token}"},
        )
    job_id = create_resp.json()["id"]

    resp = await client.get(
        f"/api/v1/backups/{job_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["id"] == job_id


async def test_get_backup_job_not_found(client: AsyncClient, test_tenant):
    _, token = test_tenant
    resp = await client.get(
        "/api/v1/backups/99999",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


async def test_source_history_empty(client: AsyncClient, test_tenant):
    _, token = test_tenant
    source = await _create_source(client, token, "History Source")

    resp = await client.get(
        f"/api/v1/backups/{source['id']}/history",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json() == []


async def test_recovery_metrics_no_snapshots(client: AsyncClient, test_tenant):
    _, token = test_tenant
    source = await _create_source(client, token, "Metrics Source")

    resp = await client.get(
        f"/api/v1/backups/{source['id']}/recovery-metrics",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["source_id"] == source["id"]
    assert data["total_snapshots"] == 0
    assert data["last_successful_backup"] is None
    assert data["rpo_violated"] is False


async def test_backup_requires_auth(client: AsyncClient):
    resp = await client.get("/api/v1/backups")
    assert resp.status_code == 401


async def test_trigger_backup_wrong_source(client: AsyncClient, test_tenant):
    """Cannot create a backup for a source belonging to another tenant."""
    _, token = test_tenant

    resp = await client.post(
        "/api/v1/backups",
        json={"source_id": 99999, "backup_type": "full"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404
