"""Tests for data source CRUD endpoints."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def _register_and_login(client: AsyncClient, email: str, password: str = "pass") -> str:
    await client.post(
        "/api/v1/auth/register",
        json={"name": "User", "email": email, "password": password},
    )
    resp = await client.post(
        "/api/v1/auth/token",
        json={"email": email, "password": password},
    )
    return resp.json()["access_token"]


async def test_create_source(client: AsyncClient, test_tenant):
    _, token = test_tenant
    resp = await client.post(
        "/api/v1/sources",
        json={
            "name": "My Files",
            "source_type": "directory",
            "path": "/data/files",
            "classification": "internal",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "My Files"
    assert data["source_type"] == "directory"
    assert data["path"] == "/data/files"


async def test_list_sources(client: AsyncClient, test_tenant):
    _, token = test_tenant
    # Create a source
    await client.post(
        "/api/v1/sources",
        json={"name": "Listed Source", "source_type": "file", "path": "/tmp/f.txt"},
        headers={"Authorization": f"Bearer {token}"},
    )
    resp = await client.get(
        "/api/v1/sources", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200
    names = [s["name"] for s in resp.json()]
    assert "Listed Source" in names


async def test_get_source(client: AsyncClient, test_tenant):
    _, token = test_tenant
    create_resp = await client.post(
        "/api/v1/sources",
        json={"name": "Specific Source", "source_type": "file", "path": "/tmp/specific.txt"},
        headers={"Authorization": f"Bearer {token}"},
    )
    source_id = create_resp.json()["id"]

    resp = await client.get(
        f"/api/v1/sources/{source_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["id"] == source_id


async def test_update_source(client: AsyncClient, test_tenant):
    _, token = test_tenant
    create_resp = await client.post(
        "/api/v1/sources",
        json={"name": "Old Name", "source_type": "directory", "path": "/tmp/d"},
        headers={"Authorization": f"Bearer {token}"},
    )
    source_id = create_resp.json()["id"]

    resp = await client.patch(
        f"/api/v1/sources/{source_id}",
        json={"name": "New Name"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "New Name"


async def test_delete_source(client: AsyncClient, test_tenant):
    _, token = test_tenant
    create_resp = await client.post(
        "/api/v1/sources",
        json={"name": "To Delete", "source_type": "file", "path": "/tmp/del.txt"},
        headers={"Authorization": f"Bearer {token}"},
    )
    source_id = create_resp.json()["id"]

    del_resp = await client.delete(
        f"/api/v1/sources/{source_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert del_resp.status_code == 204

    get_resp = await client.get(
        f"/api/v1/sources/{source_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert get_resp.status_code == 404


async def test_get_source_wrong_tenant(client: AsyncClient, test_tenant):
    """A source belonging to tenant A must not be visible to tenant B."""
    _, token_a = test_tenant

    # Create a source as tenant A
    create_resp = await client.post(
        "/api/v1/sources",
        json={"name": "Tenant A Source", "source_type": "directory", "path": "/a/data"},
        headers={"Authorization": f"Bearer {token_a}"},
    )
    source_id = create_resp.json()["id"]

    # Register tenant B and try to access tenant A's source
    token_b = await _register_and_login(client, "tenantb_sources@example.com")
    resp = await client.get(
        f"/api/v1/sources/{source_id}",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert resp.status_code == 404


async def test_source_requires_auth(client: AsyncClient):
    resp = await client.get("/api/v1/sources")
    assert resp.status_code == 401
