from datetime import datetime, timezone

from sqlalchemy import BigInteger, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
import enum


class JobStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    verifying = "verifying"
    completed = "completed"
    failed = "failed"


class BackupType(str, enum.Enum):
    full = "full"
    incremental = "incremental"


class BackupJob(Base):
    __tablename__ = "backup_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("data_sources.id"), nullable=False)
    celery_task_id: Mapped[str] = mapped_column(String(255), nullable=True)
    backup_type: Mapped[BackupType] = mapped_column(Enum(BackupType), default=BackupType.incremental)
    status: Mapped[JobStatus] = mapped_column(Enum(JobStatus), default=JobStatus.pending)
    error_message: Mapped[str] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    source = relationship("DataSource", back_populates="backup_jobs")
    snapshot = relationship("BackupSnapshot", back_populates="job", uselist=False, cascade="all, delete-orphan")


class BackupSnapshot(Base):
    __tablename__ = "backup_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("backup_jobs.id"), nullable=False)
    source_id: Mapped[int] = mapped_column(ForeignKey("data_sources.id"), nullable=False)
    merkle_root: Mapped[str] = mapped_column(String(64), nullable=False)
    parent_snapshot_id: Mapped[int] = mapped_column(ForeignKey("backup_snapshots.id"), nullable=True)
    total_size_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    dedup_size_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    chunk_count: Mapped[int] = mapped_column(Integer, default=0)
    new_chunk_count: Mapped[int] = mapped_column(Integer, default=0)
    average_entropy: Mapped[float] = mapped_column(default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    job = relationship("BackupJob", back_populates="snapshot")
    chunks = relationship("BackupChunk", back_populates="snapshot", cascade="all, delete-orphan")


class BackupChunk(Base):
    __tablename__ = "backup_chunks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("backup_snapshots.id"), nullable=False)
    chunk_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    entropy: Mapped[float] = mapped_column(default=0.0)
    is_new: Mapped[bool] = mapped_column(default=True)

    snapshot = relationship("BackupSnapshot", back_populates="chunks")
