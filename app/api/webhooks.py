"""
Webhook endpoint management and event delivery.

Tenants register HTTP URLs to receive real-time signed JSON notifications
when backup jobs complete, fail, or when anomaly alerts fire.

Every delivery is signed with HMAC-SHA256 using the endpoint's shared secret.
The signature is sent in the X-BackupOS-Signature header as:
    sha256=<hex_digest>

Receivers verify the signature before processing the payload.

Supported event types:
    backup.completed  — BackupJob finished successfully
    backup.failed     — BackupJob failed
    alert.created     — Anomaly / entropy alert raised

CRUD:
    POST   /api/v1/webhooks           — register a new endpoint
    GET    /api/v1/webhooks           — list all endpoints for the tenant
    GET    /api/v1/webhooks/{id}      — get one endpoint
    DELETE /api/v1/webhooks/{id}      — delete an endpoint
    GET    /api/v1/webhooks/{id}/deliveries  — delivery history

Delivery:
    POST   /api/v1/webhooks/deliver   — manually fire an event (testing / internal)
"""
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, HttpUrl
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_tenant
from app.core.database import get_db
from app.models.tenant import Tenant
from app.models.webhook import WebhookDelivery, WebhookEndpoint

router = APIRouter()

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class WebhookCreate(BaseModel):
    url: str
    description: Optional[str] = None
    is_active: bool = True


class WebhookResponse(BaseModel):
    id: int
    tenant_id: int
    url: str
    description: Optional[str]
    is_active: bool
    created_at: datetime
    secret_hint: str  # last 4 chars of secret — never return full secret

    model_config = {"from_attributes": True}


class DeliveryResponse(BaseModel):
    id: int
    endpoint_id: int
    event_type: str
    signature: str
    http_status: Optional[int]
    success: Optional[bool]
    error_message: Optional[str]
    delivered_at: datetime

    model_config = {"from_attributes": True}


class DeliverRequest(BaseModel):
    endpoint_id: int
    event_type: str
    payload: dict


# ---------------------------------------------------------------------------
# HMAC signing
# ---------------------------------------------------------------------------


def _sign(secret: str, body: bytes) -> str:
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


# ---------------------------------------------------------------------------
# Delivery helper
# ---------------------------------------------------------------------------

_DELIVERY_TIMEOUT = 10.0  # seconds


async def _deliver(
    db: AsyncSession,
    endpoint: WebhookEndpoint,
    event_type: str,
    payload: dict,
) -> WebhookDelivery:
    """
    Sign and POST the payload to the registered endpoint URL.

    Records a WebhookDelivery row regardless of HTTP outcome.  Never
    raises — delivery failures are soft so they don't break the caller.
    """
    body = json.dumps({"event": event_type, "data": payload, "ts": datetime.now(timezone.utc).isoformat()}).encode()
    signature = _sign(endpoint.secret, body)

    http_status: Optional[int] = None
    success: Optional[bool] = None
    error_message: Optional[str] = None

    try:
        async with httpx.AsyncClient(timeout=_DELIVERY_TIMEOUT) as client:
            resp = await client.post(
                endpoint.url,
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-BackupOS-Signature": signature,
                    "X-BackupOS-Event": event_type,
                },
            )
            http_status = resp.status_code
            success = 200 <= resp.status_code < 300
    except Exception as exc:
        error_message = str(exc)[:512]
        success = False

    delivery = WebhookDelivery(
        endpoint_id=endpoint.id,
        event_type=event_type,
        payload_json=body.decode(),
        signature=signature,
        http_status=http_status,
        success=success,
        error_message=error_message,
    )
    db.add(delivery)
    await db.commit()
    await db.refresh(delivery)
    return delivery


async def deliver_event(
    db: AsyncSession,
    tenant_id: int,
    event_type: str,
    payload: dict,
) -> list[WebhookDelivery]:
    """
    Fan out an event to all active webhook endpoints for a tenant.

    Called internally after job completion or alert creation.
    """
    result = await db.execute(
        select(WebhookEndpoint).where(
            WebhookEndpoint.tenant_id == tenant_id,
            WebhookEndpoint.is_active.is_(True),
        )
    )
    endpoints = result.scalars().all()
    deliveries = []
    for ep in endpoints:
        d = await _deliver(db, ep, event_type, payload)
        deliveries.append(d)
    return deliveries


# ---------------------------------------------------------------------------
# CRUD endpoints
# ---------------------------------------------------------------------------


@router.post("", response_model=WebhookResponse, status_code=status.HTTP_201_CREATED)
async def create_webhook(
    payload: WebhookCreate,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    """Register a new webhook endpoint. A shared secret is auto-generated."""
    secret = secrets.token_hex(32)
    ep = WebhookEndpoint(
        tenant_id=tenant.id,
        url=payload.url,
        secret=secret,
        description=payload.description,
        is_active=payload.is_active,
    )
    db.add(ep)
    await db.commit()
    await db.refresh(ep)

    return WebhookResponse(
        id=ep.id,
        tenant_id=ep.tenant_id,
        url=ep.url,
        description=ep.description,
        is_active=ep.is_active,
        created_at=ep.created_at,
        secret_hint=secret[-4:],
    )


@router.get("", response_model=list[WebhookResponse])
async def list_webhooks(
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(WebhookEndpoint)
        .where(WebhookEndpoint.tenant_id == tenant.id)
        .order_by(WebhookEndpoint.created_at.desc())
    )
    eps = result.scalars().all()
    return [
        WebhookResponse(
            id=ep.id,
            tenant_id=ep.tenant_id,
            url=ep.url,
            description=ep.description,
            is_active=ep.is_active,
            created_at=ep.created_at,
            secret_hint=ep.secret[-4:],
        )
        for ep in eps
    ]


@router.get("/{webhook_id}", response_model=WebhookResponse)
async def get_webhook(
    webhook_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    ep = await _get_owned(webhook_id, tenant, db)
    return WebhookResponse(
        id=ep.id,
        tenant_id=ep.tenant_id,
        url=ep.url,
        description=ep.description,
        is_active=ep.is_active,
        created_at=ep.created_at,
        secret_hint=ep.secret[-4:],
    )


@router.delete("/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_webhook(
    webhook_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    ep = await _get_owned(webhook_id, tenant, db)
    await db.delete(ep)
    await db.commit()


@router.get("/{webhook_id}/deliveries", response_model=list[DeliveryResponse])
async def list_deliveries(
    webhook_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    ep = await _get_owned(webhook_id, tenant, db)
    result = await db.execute(
        select(WebhookDelivery)
        .where(WebhookDelivery.endpoint_id == ep.id)
        .order_by(WebhookDelivery.delivered_at.desc())
        .limit(100)
    )
    return result.scalars().all()


@router.post("/deliver", response_model=list[DeliveryResponse])
async def manual_deliver(
    payload: DeliverRequest,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    """
    Manually fire an event to a specific endpoint.

    Useful for testing webhook integration without waiting for a real
    backup job to complete.
    """
    ep = await _get_owned(payload.endpoint_id, tenant, db)
    delivery = await _deliver(db, ep, payload.event_type, payload.payload)
    return [delivery]


# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------


async def _get_owned(
    webhook_id: int,
    tenant: Tenant,
    db: AsyncSession,
) -> WebhookEndpoint:
    result = await db.execute(
        select(WebhookEndpoint).where(
            WebhookEndpoint.id == webhook_id,
            WebhookEndpoint.tenant_id == tenant.id,
        )
    )
    ep = result.scalar_one_or_none()
    if not ep:
        raise HTTPException(status_code=404, detail="Webhook endpoint not found")
    return ep
