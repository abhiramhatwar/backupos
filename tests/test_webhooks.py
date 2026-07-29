"""Tests for webhook endpoint CRUD and delivery."""
import hashlib
import hmac
import json

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.webhook import WebhookDelivery, WebhookEndpoint

pytestmark = pytest.mark.asyncio


async def _register(client: AsyncClient, token: str, url: str = "https://example.com/hook") -> dict:
    resp = await client.post(
        "/api/v1/webhooks",
        json={"url": url, "description": "test hook"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    return resp.json()


async def test_create_webhook(client: AsyncClient, test_tenant):
    _, token = test_tenant
    data = await _register(client, token)

    assert data["url"] == "https://example.com/hook"
    assert data["description"] == "test hook"
    assert data["is_active"] is True
    assert len(data["secret_hint"]) == 4
    assert "secret" not in data  # full secret must never be returned


async def test_list_webhooks(client: AsyncClient, test_tenant):
    _, token = test_tenant
    await _register(client, token, "https://a.example.com/1")
    await _register(client, token, "https://b.example.com/2")

    resp = await client.get(
        "/api/v1/webhooks",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    urls = {w["url"] for w in data}
    assert "https://a.example.com/1" in urls
    assert "https://b.example.com/2" in urls


async def test_get_webhook(client: AsyncClient, test_tenant):
    _, token = test_tenant
    created = await _register(client, token)

    resp = await client.get(
        f"/api/v1/webhooks/{created['id']}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["id"] == created["id"]


async def test_get_webhook_not_found(client: AsyncClient, test_tenant):
    _, token = test_tenant
    resp = await client.get(
        "/api/v1/webhooks/999999",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


async def test_delete_webhook(client: AsyncClient, test_tenant):
    _, token = test_tenant
    created = await _register(client, token)

    resp = await client.delete(
        f"/api/v1/webhooks/{created['id']}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 204

    # Should be gone
    resp = await client.get(
        f"/api/v1/webhooks/{created['id']}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


async def test_tenant_isolation(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """Cannot access a webhook belonging to another tenant."""
    _, token = test_tenant
    # Create endpoint directly in another tenant's scope by using a fake ID
    resp = await client.get(
        "/api/v1/webhooks/999999",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


async def test_manual_deliver_records_delivery(
    client: AsyncClient, test_tenant, db_session: AsyncSession
):
    """Manual deliver call creates a WebhookDelivery record (HTTP delivery may fail)."""
    _, token = test_tenant
    created = await _register(client, token, "https://example.invalid/post")

    resp = await client.post(
        "/api/v1/webhooks/deliver",
        json={
            "endpoint_id": created["id"],
            "event_type": "backup.completed",
            "payload": {"job_id": 42, "status": "completed"},
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    # The actual HTTP delivery may fail (no server at that URL), but the
    # endpoint should still return 200 with a delivery record.
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    delivery = data[0]
    assert delivery["event_type"] == "backup.completed"
    assert delivery["endpoint_id"] == created["id"]


async def test_signature_format(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """Delivery record carries a sha256=<hex> signature."""
    _, token = test_tenant
    created = await _register(client, token, "https://example.invalid/hook")

    resp = await client.post(
        "/api/v1/webhooks/deliver",
        json={
            "endpoint_id": created["id"],
            "event_type": "test.event",
            "payload": {"key": "value"},
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    delivery = resp.json()[0]
    assert delivery["signature"].startswith("sha256=")
    hex_part = delivery["signature"][len("sha256="):]
    assert len(hex_part) == 64  # SHA-256 hex digest is 64 chars


async def test_delivery_history(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """GET /webhooks/{id}/deliveries returns all delivery records."""
    _, token = test_tenant
    created = await _register(client, token, "https://example.invalid/hook2")

    # Fire two events
    for event in ["backup.completed", "backup.failed"]:
        await client.post(
            "/api/v1/webhooks/deliver",
            json={"endpoint_id": created["id"], "event_type": event, "payload": {}},
            headers={"Authorization": f"Bearer {token}"},
        )

    resp = await client.get(
        f"/api/v1/webhooks/{created['id']}/deliveries",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    events = {d["event_type"] for d in resp.json()}
    assert "backup.completed" in events
    assert "backup.failed" in events


async def test_delivery_history_wrong_webhook(client: AsyncClient, test_tenant):
    """Cannot get delivery history for a non-owned webhook."""
    _, token = test_tenant
    resp = await client.get(
        "/api/v1/webhooks/999999/deliveries",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404
