from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr


class TenantCreate(BaseModel):
    name: str
    email: EmailStr
    password: str


class TenantResponse(BaseModel):
    id: int
    name: str
    email: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class TenantAPIKeyResponse(BaseModel):
    api_key: str
    message: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenRequest(BaseModel):
    email: str
    password: str
