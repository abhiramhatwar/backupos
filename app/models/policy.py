from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class BackupPolicy(Base):
    __tablename__ = "backup_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    # YAML policy definition stored as text
    policy_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    # Parsed fields for quick querying
    frequency_minutes: Mapped[int] = mapped_column(Integer, default=1440)  # daily default
    retention_days: Mapped[int] = mapped_column(Integer, default=30)
    rpo_minutes: Mapped[int] = mapped_column(Integer, default=1440)
    require_checksum: Mapped[bool] = mapped_column(Boolean, default=True)
    require_dedup: Mapped[bool] = mapped_column(Boolean, default=True)
    entropy_threshold: Mapped[float] = mapped_column(default=7.5)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    tenant = relationship("Tenant", back_populates="policies")
    attachments = relationship("PolicyAttachment", back_populates="policy", cascade="all, delete-orphan")


class PolicyAttachment(Base):
    __tablename__ = "policy_attachments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("backup_policies.id"), nullable=False)
    source_id: Mapped[int] = mapped_column(ForeignKey("data_sources.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    policy = relationship("BackupPolicy", back_populates="attachments")
    source = relationship("DataSource", back_populates="policy_attachments")
