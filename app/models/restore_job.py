from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.backup import JobStatus


class RestoreJob(Base):
    __tablename__ = "restore_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("data_sources.id"), nullable=False)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("backup_snapshots.id"), nullable=True)
    celery_task_id: Mapped[str] = mapped_column(String(255), nullable=True)
    restore_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    status: Mapped[JobStatus] = mapped_column(Enum(JobStatus), default=JobStatus.pending)
    error_message: Mapped[str] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    source = relationship("DataSource")
    snapshot = relationship("BackupSnapshot")
