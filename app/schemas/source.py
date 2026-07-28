from datetime import datetime
from typing import Optional

from pydantic import BaseModel

from app.models.source import DataClassification, SourceType


class DataSourceCreate(BaseModel):
    name: str
    source_type: SourceType
    path: str
    classification: DataClassification = DataClassification.internal
    tags: dict = {}


class DataSourceUpdate(BaseModel):
    name: Optional[str] = None
    classification: Optional[DataClassification] = None
    tags: Optional[dict] = None


class DataSourceResponse(BaseModel):
    id: int
    name: str
    source_type: SourceType
    path: str
    classification: DataClassification
    tags: str
    created_at: datetime

    model_config = {"from_attributes": True}
