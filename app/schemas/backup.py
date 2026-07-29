from datetime import datetime
from typing import Optional

from pydantic import BaseModel

from app.models.backup import BackupType, JobStatus


class BackupJobCreate(BaseModel):
    source_id: int
    backup_type: BackupType = BackupType.incremental


class BackupJobResponse(BaseModel):
    id: int
    source_id: int
    celery_task_id: Optional[str]
    backup_type: BackupType
    status: JobStatus
    error_message: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


class SnapshotResponse(BaseModel):
    id: int
    job_id: int
    source_id: int
    merkle_root: str
    parent_snapshot_id: Optional[int]
    total_size_bytes: int
    dedup_size_bytes: int
    dedup_ratio: float = 0.0
    chunk_count: int
    new_chunk_count: int
    average_entropy: float
    created_at: datetime
    locked_until: Optional[datetime] = None
    last_verified_at: Optional[datetime] = None
    verification_status: Optional[str] = None

    model_config = {"from_attributes": True}

    @classmethod
    def from_orm_with_ratio(cls, obj):
        data = cls.model_validate(obj)
        if obj.total_size_bytes > 0:
            saved = obj.total_size_bytes - obj.dedup_size_bytes
            data.dedup_ratio = round(saved / obj.total_size_bytes, 4)
        return data


class RecoveryMetrics(BaseModel):
    source_id: int
    last_successful_backup: Optional[datetime]
    current_rpo_minutes: Optional[float]
    policy_rpo_minutes: Optional[int]
    rpo_violated: bool
    estimated_rto_minutes: Optional[float]
    total_snapshots: int
    latest_snapshot_id: Optional[int]
    latest_merkle_root: Optional[str]
