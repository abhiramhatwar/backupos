"""HTTP endpoint tests for backup policy CRUD and the PATCH update endpoint."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio

_VALID_YAML = """\
frequency_minutes: 1440
retention_days: 30
rpo_minutes: 1440
require_checksum: true
require_dedup: true
entropy_threshold: 7.5
"""


async def _register(client: AsyncClient, suffix: str) -> str:
    """Register a unique tenant and return a JWT token."""
    email = f"policy_{suffix}@example.com"
    await client.post(
        "/api/v1/auth/register",
        json={"name": "Policy Tester", "email": email, "password": "testpass123"},
    )
    resp = await client.post(
        "/api/v1/auth/token",
        json={"email": email, "password": "testpass123"},
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


async def _create_policy(client: AsyncClient, token: str, name: str = "Test Policy") -> dict:
    resp = await client.post(
        "/api/v1/policies",
        json={"name": name, "policy_yaml": _VALID_YAML},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    return resp.json()


async def _create_source(client: AsyncClient, token: str, name: str = "Source") -> dict:
    resp = await client.post(
        "/api/v1/sources",
        json={"name": name, "source_type": "directory", "path": "/tmp/ps"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    return resp.json()


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------


async def test_create_policy(client: AsyncClient):
    token = await _register(client, "create")
    resp = await client.post(
        "/api/v1/policies",
        json={"name": "Daily Backup", "policy_yaml": _VALID_YAML},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Daily Backup"
    assert data["frequency_minutes"] == 1440
    assert data["retention_days"] == 30
    assert data["rpo_minutes"] == 1440
    assert data["is_active"] is True


async def test_create_policy_invalid_yaml(client: AsyncClient):
    token = await _register(client, "invalid_yaml")
    resp = await client.post(
        "/api/v1/policies",
        json={"name": "Bad", "policy_yaml": "[unclosed bracket"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 422


async def test_create_policy_missing_required_field(client: AsyncClient):
    token = await _register(client, "missing_field")
    resp = await client.post(
        "/api/v1/policies",
        json={"name": "Incomplete", "policy_yaml": "frequency_minutes: 1440"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 422


async def test_create_policy_requires_auth(client: AsyncClient):
    resp = await client.post(
        "/api/v1/policies",
        json={"name": "X", "policy_yaml": _VALID_YAML},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# List / Get
# ---------------------------------------------------------------------------


async def test_list_policies(client: AsyncClient):
    token = await _register(client, "list")
    await _create_policy(client, token, "Policy Alpha")
    await _create_policy(client, token, "Policy Beta")

    resp = await client.get("/api/v1/policies", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    names = [p["name"] for p in resp.json()]
    assert "Policy Alpha" in names
    assert "Policy Beta" in names


async def test_list_policies_requires_auth(client: AsyncClient):
    resp = await client.get("/api/v1/policies")
    assert resp.status_code == 401


async def test_get_policy(client: AsyncClient):
    token = await _register(client, "get")
    policy = await _create_policy(client, token)

    resp = await client.get(
        f"/api/v1/policies/{policy['id']}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["id"] == policy["id"]


async def test_get_policy_not_found(client: AsyncClient):
    token = await _register(client, "get_missing")
    resp = await client.get(
        "/api/v1/policies/99999",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


async def test_policy_tenant_isolation(client: AsyncClient):
    token_a = await _register(client, "iso_a")
    token_b = await _register(client, "iso_b")

    policy = await _create_policy(client, token_a)
    resp = await client.get(
        f"/api/v1/policies/{policy['id']}",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Update (PATCH)
# ---------------------------------------------------------------------------


async def test_update_policy_name(client: AsyncClient):
    token = await _register(client, "upd_name")
    policy = await _create_policy(client, token, "Original")

    resp = await client.patch(
        f"/api/v1/policies/{policy['id']}",
        json={"name": "Renamed"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "Renamed"


async def test_update_policy_yaml_recalculates_columns(client: AsyncClient):
    token = await _register(client, "upd_yaml")
    policy = await _create_policy(client, token)

    new_yaml = "frequency_minutes: 720\nretention_days: 60\nrpo_minutes: 480\n"
    resp = await client.patch(
        f"/api/v1/policies/{policy['id']}",
        json={"policy_yaml": new_yaml},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["frequency_minutes"] == 720
    assert data["retention_days"] == 60
    assert data["rpo_minutes"] == 480


async def test_update_policy_deactivate(client: AsyncClient):
    token = await _register(client, "deactivate")
    policy = await _create_policy(client, token)

    resp = await client.patch(
        f"/api/v1/policies/{policy['id']}",
        json={"is_active": False},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["is_active"] is False


async def test_update_policy_not_found(client: AsyncClient):
    token = await _register(client, "upd_missing")
    resp = await client.patch(
        "/api/v1/policies/99999",
        json={"name": "Ghost"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


async def test_update_policy_invalid_yaml_rejected(client: AsyncClient):
    token = await _register(client, "upd_bad_yaml")
    policy = await _create_policy(client, token)

    resp = await client.patch(
        f"/api/v1/policies/{policy['id']}",
        json={"policy_yaml": "[unclosed"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Attach
# ---------------------------------------------------------------------------


async def test_attach_policy_to_source(client: AsyncClient):
    token = await _register(client, "attach")
    policy = await _create_policy(client, token)
    source = await _create_source(client, token)

    resp = await client.post(
        f"/api/v1/policies/{policy['id']}/attach",
        json={"source_id": source["id"]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["policy_id"] == policy["id"]
    assert data["source_id"] == source["id"]


async def test_attach_policy_duplicate_returns_409(client: AsyncClient):
    token = await _register(client, "dup_attach")
    policy = await _create_policy(client, token)
    source = await _create_source(client, token)

    await client.post(
        f"/api/v1/policies/{policy['id']}/attach",
        json={"source_id": source["id"]},
        headers={"Authorization": f"Bearer {token}"},
    )
    resp = await client.post(
        f"/api/v1/policies/{policy['id']}/attach",
        json={"source_id": source["id"]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 409


async def test_attach_nonexistent_source_returns_404(client: AsyncClient):
    token = await _register(client, "attach_missing_src")
    policy = await _create_policy(client, token)

    resp = await client.post(
        f"/api/v1/policies/{policy['id']}/attach",
        json={"source_id": 99999},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------


async def test_delete_policy(client: AsyncClient):
    token = await _register(client, "delete")
    policy = await _create_policy(client, token)
    policy_id = policy["id"]

    del_resp = await client.delete(
        f"/api/v1/policies/{policy_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert del_resp.status_code == 204

    get_resp = await client.get(
        f"/api/v1/policies/{policy_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert get_resp.status_code == 404


async def test_delete_policy_not_found(client: AsyncClient):
    token = await _register(client, "del_missing")
    resp = await client.delete(
        "/api/v1/policies/99999",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404
