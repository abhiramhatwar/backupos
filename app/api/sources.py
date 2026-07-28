import json

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_event
from app.core.auth import get_current_tenant
from app.core.database import get_db
from app.models.source import DataSource
from app.models.tenant import Tenant
from app.schemas.source import DataSourceCreate, DataSourceResponse, DataSourceUpdate

router = APIRouter()


@router.post("", response_model=DataSourceResponse, status_code=status.HTTP_201_CREATED)
async def create_source(
    payload: DataSourceCreate,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    source = DataSource(
        tenant_id=tenant.id,
        name=payload.name,
        source_type=payload.source_type,
        path=payload.path,
        classification=payload.classification,
        tags=json.dumps(payload.tags),
    )
    db.add(source)
    await db.commit()
    await db.refresh(source)
    await log_event(db, tenant.id, "source.created", "DataSource", str(source.id), tenant.email)
    return source


@router.get("", response_model=list[DataSourceResponse])
async def list_sources(
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    result = await db.execute(
        select(DataSource)
        .where(DataSource.tenant_id == tenant.id)
        .offset(skip)
        .limit(limit)
    )
    return result.scalars().all()


@router.get("/{source_id}", response_model=DataSourceResponse)
async def get_source(
    source_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(DataSource).where(DataSource.id == source_id, DataSource.tenant_id == tenant.id)
    )
    source = result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Data source not found")
    return source


@router.patch("/{source_id}", response_model=DataSourceResponse)
async def update_source(
    source_id: int,
    payload: DataSourceUpdate,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(DataSource).where(DataSource.id == source_id, DataSource.tenant_id == tenant.id)
    )
    source = result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Data source not found")

    if payload.name is not None:
        source.name = payload.name
    if payload.classification is not None:
        source.classification = payload.classification
    if payload.tags is not None:
        source.tags = json.dumps(payload.tags)

    await db.commit()
    await db.refresh(source)
    await log_event(db, tenant.id, "source.updated", "DataSource", str(source.id), tenant.email)
    return source


@router.delete("/{source_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_source(
    source_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(DataSource).where(DataSource.id == source_id, DataSource.tenant_id == tenant.id)
    )
    source = result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Data source not found")
    await log_event(db, tenant.id, "source.deleted", "DataSource", str(source_id), tenant.email)
    await db.delete(source)
    await db.commit()
