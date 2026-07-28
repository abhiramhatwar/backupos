from datetime import datetime
from typing import Optional

from pydantic import BaseModel, field_validator
import yaml


class PolicyCreate(BaseModel):
    name: str
    description: Optional[str] = None
    policy_yaml: str

    @field_validator("policy_yaml")
    @classmethod
    def validate_yaml(cls, v):
        try:
            data = yaml.safe_load(v)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML: {e}")
        required = ["frequency_minutes", "retention_days", "rpo_minutes"]
        for field in required:
            if field not in data:
                raise ValueError(f"Missing required policy field: {field}")
        return v


class PolicyAttachRequest(BaseModel):
    source_id: int


class PolicyResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    policy_yaml: str
    frequency_minutes: int
    retention_days: int
    rpo_minutes: int
    require_checksum: bool
    require_dedup: bool
    entropy_threshold: float
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}
