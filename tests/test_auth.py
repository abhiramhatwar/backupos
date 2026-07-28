"""Tests for authentication endpoints."""
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_register(client: AsyncClient):
    resp = await client.post(
        "/api/v1/auth/register",
        json={"name": "Alice", "email": "alice@example.com", "password": "secret123"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["email"] == "alice@example.com"
    assert data["is_active"] is True
    assert "id" in data


async def test_register_duplicate_email(client: AsyncClient):
    payload = {"name": "Bob", "email": "bob@example.com", "password": "pass"}
    await client.post("/api/v1/auth/register", json=payload)
    resp = await client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 400
    assert "already registered" in resp.json()["detail"].lower()


async def test_login_success(client: AsyncClient):
    await client.post(
        "/api/v1/auth/register",
        json={"name": "Carol", "email": "carol@example.com", "password": "mypassword"},
    )
    resp = await client.post(
        "/api/v1/auth/token",
        json={"email": "carol@example.com", "password": "mypassword"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


async def test_login_wrong_password(client: AsyncClient):
    await client.post(
        "/api/v1/auth/register",
        json={"name": "Dave", "email": "dave@example.com", "password": "rightpass"},
    )
    resp = await client.post(
        "/api/v1/auth/token",
        json={"email": "dave@example.com", "password": "wrongpass"},
    )
    assert resp.status_code == 401


async def test_login_unknown_email(client: AsyncClient):
    resp = await client.post(
        "/api/v1/auth/token",
        json={"email": "nobody@example.com", "password": "pass"},
    )
    assert resp.status_code == 401


async def test_me(client: AsyncClient, test_tenant):
    tenant, token = test_tenant
    resp = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == tenant.id
    assert data["email"] == tenant.email


async def test_me_no_auth(client: AsyncClient):
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code == 401


async def test_me_with_api_key(client: AsyncClient, test_tenant):
    tenant, _ = test_tenant
    resp = await client.get(
        "/api/v1/auth/me",
        headers={"X-API-Key": tenant.api_key},
    )
    assert resp.status_code == 200
    assert resp.json()["id"] == tenant.id


async def test_rotate_api_key(client: AsyncClient, test_tenant):
    tenant, token = test_tenant
    resp = await client.post(
        "/api/v1/auth/api-key/rotate",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "api_key" in data
    assert data["api_key"].startswith("bos_")
    assert data["api_key"] != tenant.api_key
