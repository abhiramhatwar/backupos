"""Tests for the signed audit log export endpoint."""
import hashlib
import hmac
import json
from datetime import datetime, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.compliance import _canonical, _derive_key, _sign_export
from app.core.audit import log_event

pytestmark = pytest.mark.asyncio


async def _seed_events(db: AsyncSession, tenant_id: int, n: int = 3) -> None:
    for i in range(n):
        await log_event(
            db, tenant_id, f"backup.completed.{i}", "BackupJob", i,
            "test@example.com", detail=f"run {i}",
        )
    await db.commit()


async def test_export_returns_events(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """Export returns all audit events for the tenant."""
    tenant, token = test_tenant
    await _seed_events(db_session, tenant.id, 3)

    resp = await client.get(
        "/api/v1/compliance/audit-export",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["event_count"] >= 3
    assert len(data["events"]) >= 3
    assert data["algorithm"] == "HMAC-SHA256"
    assert data["signature"].startswith("sha256=")


async def test_signature_is_reproducible(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """Calling the export twice with same filters produces the same signature."""
    tenant, token = test_tenant
    await _seed_events(db_session, tenant.id, 2)

    resp1 = await client.get(
        "/api/v1/compliance/audit-export",
        headers={"Authorization": f"Bearer {token}"},
    )
    resp2 = await client.get(
        "/api/v1/compliance/audit-export",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp1.json()["signature"] == resp2.json()["signature"]


async def test_verify_endpoint_valid(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """Verify endpoint confirms a freshly exported signature as valid."""
    tenant, token = test_tenant
    await _seed_events(db_session, tenant.id, 2)

    export = (
        await client.get(
            "/api/v1/compliance/audit-export",
            headers={"Authorization": f"Bearer {token}"},
        )
    ).json()

    resp = await client.get(
        "/api/v1/compliance/audit-export/verify",
        params={"signature": export["signature"]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["valid"] is True


async def test_verify_endpoint_tampered(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """Verify endpoint rejects a tampered signature."""
    tenant, token = test_tenant
    await _seed_events(db_session, tenant.id, 1)

    resp = await client.get(
        "/api/v1/compliance/audit-export/verify",
        params={"signature": "sha256=" + "0" * 64},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["valid"] is False


async def test_event_type_filter(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """event_type query param narrows the exported events."""
    tenant, token = test_tenant
    await log_event(db_session, tenant.id, "backup.completed", "BackupJob", 1, "a@b.com")
    await log_event(db_session, tenant.id, "alert.created", "AnomalyAlert", 2, "a@b.com")
    await db_session.commit()

    resp = await client.get(
        "/api/v1/compliance/audit-export",
        params={"event_type": "backup."},
        headers={"Authorization": f"Bearer {token}"},
    )
    data = resp.json()
    assert all(e["event_type"].startswith("backup.") for e in data["events"])


async def test_limit_parameter(client: AsyncClient, test_tenant, db_session: AsyncSession):
    """limit query param caps the number of exported events."""
    tenant, token = test_tenant
    await _seed_events(db_session, tenant.id, 10)

    resp = await client.get(
        "/api/v1/compliance/audit-export",
        params={"limit": 3},
        headers={"Authorization": f"Bearer {token}"},
    )
    data = resp.json()
    assert data["event_count"] == 3
    assert len(data["events"]) == 3


async def test_empty_export_has_valid_signature(client: AsyncClient, test_tenant):
    """Exporting with no matching events still produces a valid (empty) signature."""
    _, token = test_tenant
    resp = await client.get(
        "/api/v1/compliance/audit-export",
        params={"event_type": "nonexistent.type.xyz"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["event_count"] == 0
    assert data["signature"].startswith("sha256=")


# ---------------------------------------------------------------------------
# Unit tests for signing helpers (sync — no asyncio mark needed)
# ---------------------------------------------------------------------------

import pytest as _pytest


@_pytest.mark.no_cover
def test_canonical_is_deterministic():
    """Same dict always produces the same canonical string."""
    d = {"z": 1, "a": "hello", "m": None}
    assert _canonical(d) == _canonical(d)
    assert _canonical(d) == _canonical({"m": None, "z": 1, "a": "hello"})


@_pytest.mark.no_cover
def test_derive_key_differs_per_tenant():
    """Different tenant IDs produce different derived keys."""
    assert _derive_key(1) != _derive_key(2)


@_pytest.mark.no_cover
def test_sign_export_empty():
    """Signing an empty event list produces a stable sha256= signature."""
    sig = _sign_export(1, [])
    assert sig.startswith("sha256=")
    assert len(sig) == len("sha256=") + 64
