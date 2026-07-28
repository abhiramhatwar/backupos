import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    to_encode["exp"] = expire
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


def generate_api_key() -> str:
    return f"bos_{secrets.token_urlsafe(32)}"


async def get_current_tenant(
    token: Optional[str] = Depends(oauth2_scheme),
    api_key: Optional[str] = Security(api_key_header),
    db: AsyncSession = Depends(get_db),
):
    from app.models.tenant import Tenant

    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if api_key:
        result = await db.execute(select(Tenant).where(Tenant.api_key == api_key, Tenant.is_active == True))
        tenant = result.scalar_one_or_none()
        if not tenant:
            raise credentials_exc
        return tenant

    if not token:
        raise credentials_exc

    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        tenant_id: str = payload.get("sub")
        if tenant_id is None:
            raise credentials_exc
    except JWTError:
        raise credentials_exc

    result = await db.execute(select(Tenant).where(Tenant.id == int(tenant_id), Tenant.is_active == True))
    tenant = result.scalar_one_or_none()
    if not tenant:
        raise credentials_exc
    return tenant
