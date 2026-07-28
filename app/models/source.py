from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
import enum


class SourceType(str, enum.Enum):
    directory = "directory"
    database = "database"
    file = "file"


class DataClassification(str, enum.Enum):
    public = "public"
    internal = "internal"
    confidential = "confidential"
    pii = "pii"
    financial = "financial"


class DataSource(Base):
    __tablename__ = "data_sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    source_type: Mapped[SourceType] = mapped_column(Enum(SourceType), nullable=False)
    path: Mapped[str] = mapped_column(String(1024), nullable=False)
    classification: Mapped[DataClassification] = mapped_column(
        Enum(DataClassification), default=DataClassification.internal
    )
    tags: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    tenant = relationship("Tenant", back_populates="sources")
    backup_jobs = relationship("BackupJob", back_populates="source", cascade="all, delete-orphan")
    policy_attachments = relationship("PolicyAttachment", back_populates="source", cascade="all, delete-orphan")
    anomaly_alerts = relationship("AnomalyAlert", back_populates="source", cascade="all, delete-orphan")
