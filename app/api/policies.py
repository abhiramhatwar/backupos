import yaml
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_event
from app.core.auth import get_current_tenant
from app.core.database import get_db
from app.models.policy import BackupPolicy, PolicyAttachment
from app.models.source import DataSource
from app.models.tenant import Tenant
from app.schemas.policy import PolicyAttachRequest, PolicyCreate, PolicyResponse, PolicyUpdate

router = APIRouter()


def _parse_policy_yaml(policy_yaml: str) -> dict:
    data = yaml.safe_load(policy_yaml)
    return {
        "frequency_minutes": int(data.get("frequency_minutes", 1440)),
        "retention_days": int(data.get("retention_days", 30)),
        "rpo_minutes": int(data.get("rpo_minutes", 1440)),
        "require_checksum": bool(data.get("require_checksum", True)),
        "require_dedup": bool(data.get("require_dedup", True)),
        "entropy_threshold": float(data.get("entropy_threshold", 7.5)),
    }


@router.post("", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    payload: PolicyCreate,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    parsed = _parse_policy_yaml(payload.policy_yaml)
    policy = BackupPolicy(
        tenant_id=tenant.id,
        name=payload.name,
        description=payload.description,
        policy_yaml=payload.policy_yaml,
        **parsed,
    )
    db.add(policy)
    await log_event(db, tenant.id, "policy.created", "BackupPolicy", None, tenant.email)
    await db.commit()
    await db.refresh(policy)
    return policy


@router.get("", response_model=list[PolicyResponse])
async def list_policies(
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    result = await db.execute(
        select(BackupPolicy)
        .where(BackupPolicy.tenant_id == tenant.id)
        .offset(skip)
        .limit(limit)
    )
    return result.scalars().all()


@router.get("/{policy_id}", response_model=PolicyResponse)
async def get_policy(
    policy_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(BackupPolicy).where(
            BackupPolicy.id == policy_id,
            BackupPolicy.tenant_id == tenant.id,
        )
    )
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy


@router.patch("/{policy_id}", response_model=PolicyResponse)
async def update_policy(
    policy_id: int,
    payload: PolicyUpdate,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(BackupPolicy).where(
            BackupPolicy.id == policy_id,
            BackupPolicy.tenant_id == tenant.id,
        )
    )
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    if payload.name is not None:
        policy.name = payload.name
    if payload.description is not None:
        policy.description = payload.description
    if payload.policy_yaml is not None:
        parsed = _parse_policy_yaml(payload.policy_yaml)
        policy.policy_yaml = payload.policy_yaml
        for k, v in parsed.items():
            setattr(policy, k, v)
    if payload.is_active is not None:
        policy.is_active = payload.is_active

    await log_event(db, tenant.id, "policy.updated", "BackupPolicy", str(policy_id), tenant.email)
    await db.commit()
    await db.refresh(policy)
    return policy


@router.post("/{policy_id}/attach", status_code=status.HTTP_201_CREATED)
async def attach_policy(
    policy_id: int,
    payload: PolicyAttachRequest,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    policy_result = await db.execute(
        select(BackupPolicy).where(
            BackupPolicy.id == policy_id,
            BackupPolicy.tenant_id == tenant.id,
        )
    )
    policy = policy_result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    source_result = await db.execute(
        select(DataSource).where(
            DataSource.id == payload.source_id,
            DataSource.tenant_id == tenant.id,
        )
    )
    source = source_result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Data source not found")

    existing_result = await db.execute(
        select(PolicyAttachment).where(
            PolicyAttachment.policy_id == policy_id,
            PolicyAttachment.source_id == payload.source_id,
        )
    )
    if existing_result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Policy already attached to this source")

    attachment = PolicyAttachment(policy_id=policy_id, source_id=payload.source_id)
    db.add(attachment)
    await log_event(db, tenant.id, "policy.attached", "BackupPolicy", str(policy_id), tenant.email,
                    detail=f"source_id={payload.source_id}")
    await db.commit()
    return {"policy_id": policy_id, "source_id": payload.source_id, "message": "Policy attached"}


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(
    policy_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(BackupPolicy).where(
            BackupPolicy.id == policy_id,
            BackupPolicy.tenant_id == tenant.id,
        )
    )
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    await log_event(db, tenant.id, "policy.deleted", "BackupPolicy", str(policy_id), tenant.email)
    await db.delete(policy)
    await db.commit()
