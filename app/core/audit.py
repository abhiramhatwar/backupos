"""
Audit log writer — append-only events persisted to PostgreSQL.

Call log_event() from any route to record an immutable audit trail entry.
"""
from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog


async def log_event(
    db: AsyncSession,
    tenant_id: int,
    event_type: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    actor: str | None = None,
    detail: str | None = None,
) -> None:
    entry = AuditLog(
        tenant_id=tenant_id,
        event_type=event_type,
        resource_type=resource_type,
        resource_id=resource_id,
        actor=actor,
        detail=detail,
    )
    db.add(entry)
    await db.commit()
