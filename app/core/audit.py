"""
Audit log writer — append-only events persisted to PostgreSQL.

Call log_event() from any route to record an immutable audit trail entry.
The function only adds the entry to the session; the caller is responsible
for committing so that the audit record and the business operation share
the same transaction and either both succeed or both roll back.
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
    # No commit here — caller commits so the audit entry and the triggering
    # business record are written atomically in one transaction.
