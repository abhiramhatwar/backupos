"""
Compliance & audit log export.

GET /api/v1/compliance/audit-export
  Exports the full audit log for the authenticated tenant as a signed JSON
  document.  The export is intended as a tamper-evident compliance artifact
  suitable for SOC 2 / HIPAA audit trails.

Signing scheme
--------------
Each audit event row is serialised to a stable JSON string (keys sorted,
no extra whitespace).  All rows are concatenated and an HMAC-SHA256 digest
is computed over the concatenated bytes using a per-tenant derived key:

    key      = HMAC-SHA256(EXPORT_SECRET, tenant_id_bytes)
    body     = canonical_json_of_each_row joined by '\\n'
    signature = HMAC-SHA256(key, body)

The exported document includes:
    {
      "tenant_id": 1,
      "exported_at": "2024-...",
      "event_count": 42,
      "events": [...],
      "signature": "sha256=<hex>",
      "algorithm": "HMAC-SHA256"
    }

Verifiers can reproduce the signature by:
  1. Sorting events by id ascending.
  2. Serialising each event to stable JSON (sorted keys).
  3. Joining with '\\n'.
  4. Computing HMAC-SHA256 over the result with the same key derivation.

Query parameters
----------------
  - since      ISO-8601 datetime; only return events after this time
  - until      ISO-8601 datetime; only return events before this time
  - event_type filter to a specific event_type prefix (e.g. "backup.")
  - limit      max events to export (default 10000, max 50000)
"""
import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_tenant
from app.core.config import settings
from app.core.database import get_db
from app.models.audit import AuditLog
from app.models.tenant import Tenant

router = APIRouter()

_EXPORT_SECRET = getattr(settings, "secret_key", "backupos-audit-export-secret")


# ---------------------------------------------------------------------------
# Signing helpers
# ---------------------------------------------------------------------------


def _derive_key(tenant_id: int) -> bytes:
    """Derive a per-tenant signing key from the export secret."""
    return hmac.new(
        _EXPORT_SECRET.encode(),
        str(tenant_id).encode(),
        hashlib.sha256,
    ).digest()


def _canonical(event: dict) -> str:
    return json.dumps(event, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _sign_export(tenant_id: int, events: list[dict]) -> str:
    key = _derive_key(tenant_id)
    body = "\n".join(_canonical(e) for e in events).encode()
    digest = hmac.new(key, body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


class AuditEventExport(BaseModel):
    id: int
    tenant_id: int
    event_type: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    actor: Optional[str]
    detail: Optional[str]
    created_at: datetime


class AuditExportResponse(BaseModel):
    tenant_id: int
    exported_at: datetime
    event_count: int
    since: Optional[datetime]
    until: Optional[datetime]
    events: list[AuditEventExport]
    signature: str
    algorithm: str


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.get("/audit-export", response_model=AuditExportResponse)
async def export_audit_log(
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    since: Optional[datetime] = Query(None, description="Export events after this ISO-8601 datetime"),
    until: Optional[datetime] = Query(None, description="Export events before this ISO-8601 datetime"),
    event_type: Optional[str] = Query(None, description="Filter by event_type prefix (e.g. 'backup.')"),
    limit: int = Query(10_000, ge=1, le=50_000),
):
    """
    Export the full tenant audit log as a signed compliance artifact.

    The response body includes an HMAC-SHA256 signature over all event rows
    (sorted by id, canonical JSON) that lets downstream verifiers confirm the
    export was not tampered with after it left this API.

    Supports optional time-range and event-type filters to narrow the export
    for a specific audit period or control domain.
    """
    stmt = (
        select(AuditLog)
        .where(AuditLog.tenant_id == tenant.id)
        .order_by(AuditLog.id.asc())
        .limit(limit)
    )

    if since:
        if since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)
        stmt = stmt.where(AuditLog.created_at >= since)

    if until:
        if until.tzinfo is None:
            until = until.replace(tzinfo=timezone.utc)
        stmt = stmt.where(AuditLog.created_at <= until)

    if event_type:
        stmt = stmt.where(AuditLog.event_type.like(f"{event_type}%"))

    rows = (await db.execute(stmt)).scalars().all()

    events: list[AuditEventExport] = [
        AuditEventExport(
            id=r.id,
            tenant_id=r.tenant_id,
            event_type=r.event_type,
            resource_type=r.resource_type,
            resource_id=r.resource_id,
            actor=r.actor,
            detail=r.detail,
            created_at=r.created_at,
        )
        for r in rows
    ]

    event_dicts = [e.model_dump(mode="json") for e in events]
    signature = _sign_export(tenant.id, event_dicts)

    exported_at = datetime.now(timezone.utc)

    return AuditExportResponse(
        tenant_id=tenant.id,
        exported_at=exported_at,
        event_count=len(events),
        since=since,
        until=until,
        events=events,
        signature=signature,
        algorithm="HMAC-SHA256",
    )


@router.get("/audit-export/verify")
async def verify_export_signature(
    signature: str = Query(..., description="Signature from a prior export (sha256=<hex>)"),
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    since: Optional[datetime] = Query(None),
    until: Optional[datetime] = Query(None),
    event_type: Optional[str] = Query(None),
    limit: int = Query(10_000, ge=1, le=50_000),
):
    """
    Re-derive the audit export signature and confirm it matches the supplied value.

    Useful for downstream systems that want to verify a stored export is still
    intact without re-downloading the full payload.
    """
    stmt = (
        select(AuditLog)
        .where(AuditLog.tenant_id == tenant.id)
        .order_by(AuditLog.id.asc())
        .limit(limit)
    )
    if since:
        if since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)
        stmt = stmt.where(AuditLog.created_at >= since)
    if until:
        if until.tzinfo is None:
            until = until.replace(tzinfo=timezone.utc)
        stmt = stmt.where(AuditLog.created_at <= until)
    if event_type:
        stmt = stmt.where(AuditLog.event_type.like(f"{event_type}%"))

    rows = (await db.execute(stmt)).scalars().all()
    events = [
        AuditEventExport(
            id=r.id,
            tenant_id=r.tenant_id,
            event_type=r.event_type,
            resource_type=r.resource_type,
            resource_id=r.resource_id,
            actor=r.actor,
            detail=r.detail,
            created_at=r.created_at,
        )
        for r in rows
    ]
    event_dicts = [e.model_dump(mode="json") for e in events]
    expected = _sign_export(tenant.id, event_dicts)
    is_valid = hmac.compare_digest(signature, expected)

    return {
        "valid": is_valid,
        "event_count": len(events),
        "algorithm": "HMAC-SHA256",
    }
