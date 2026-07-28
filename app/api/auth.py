from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import (
    create_access_token,
    generate_api_key,
    get_current_tenant,
    hash_password,
    verify_password,
)
from app.core.database import get_db
from app.models.tenant import Tenant
from app.schemas.tenant import TenantAPIKeyResponse, TenantCreate, TenantResponse, TokenRequest, TokenResponse

router = APIRouter()


@router.post("/register", response_model=TenantResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: TenantCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Tenant).where(Tenant.email == payload.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    tenant = Tenant(
        name=payload.name,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        api_key=generate_api_key(),
    )
    db.add(tenant)
    await db.commit()
    await db.refresh(tenant)
    return tenant


@router.post("/token", response_model=TokenResponse)
async def login(payload: TokenRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Tenant).where(Tenant.email == payload.email))
    tenant = result.scalar_one_or_none()
    if not tenant or not verify_password(payload.password, tenant.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": str(tenant.id)})
    return {"access_token": token}


@router.post("/api-key/rotate", response_model=TenantAPIKeyResponse)
async def rotate_api_key(tenant: Tenant = Depends(get_current_tenant), db: AsyncSession = Depends(get_db)):
    tenant.api_key = generate_api_key()
    await db.commit()
    await db.refresh(tenant)
    return {"api_key": tenant.api_key, "message": "API key rotated successfully"}


@router.get("/me", response_model=TenantResponse)
async def me(tenant: Tenant = Depends(get_current_tenant)):
    return tenant
