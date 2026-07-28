"""Initial schema — all tables

Revision ID: 001
Revises:
Create Date: 2024-01-01 00:00:00.000000
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("api_key", sa.String(64), nullable=True, unique=True),
        sa.Column("is_active", sa.Boolean(), default=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "data_sources",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("source_type", sa.String(50), nullable=False),
        sa.Column("classification", sa.String(50), nullable=True),
        sa.Column("tags", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), default=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_data_sources_tenant_id", "data_sources", ["tenant_id"])

    op.create_table(
        "backup_policies",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("policy_yaml", sa.Text(), nullable=False),
        sa.Column("frequency_minutes", sa.Integer(), default=1440),
        sa.Column("retention_days", sa.Integer(), default=30),
        sa.Column("rpo_minutes", sa.Integer(), default=1440),
        sa.Column("require_checksum", sa.Boolean(), default=True),
        sa.Column("require_dedup", sa.Boolean(), default=True),
        sa.Column("entropy_threshold", sa.Float(), default=7.5),
        sa.Column("is_active", sa.Boolean(), default=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "policy_attachments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("policy_id", sa.Integer(), sa.ForeignKey("backup_policies.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("data_sources.id", ondelete="CASCADE"), nullable=False),
    )
    op.create_unique_constraint("uq_policy_source", "policy_attachments", ["policy_id", "source_id"])

    op.create_table(
        "backup_jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("data_sources.id"), nullable=False),
        sa.Column("celery_task_id", sa.String(255), nullable=True),
        sa.Column("backup_type", sa.String(50), nullable=False),
        sa.Column("status", sa.String(50), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_backup_jobs_source_id", "backup_jobs", ["source_id"])

    op.create_table(
        "backup_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("job_id", sa.Integer(), sa.ForeignKey("backup_jobs.id"), nullable=False),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("data_sources.id"), nullable=False),
        sa.Column("merkle_root", sa.String(64), nullable=False),
        sa.Column("parent_snapshot_id", sa.Integer(), sa.ForeignKey("backup_snapshots.id"), nullable=True),
        sa.Column("total_size_bytes", sa.BigInteger(), default=0),
        sa.Column("dedup_size_bytes", sa.BigInteger(), default=0),
        sa.Column("chunk_count", sa.Integer(), default=0),
        sa.Column("new_chunk_count", sa.Integer(), default=0),
        sa.Column("average_entropy", sa.Float(), default=0.0),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_backup_snapshots_source_id", "backup_snapshots", ["source_id"])

    op.create_table(
        "backup_chunks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("snapshot_id", sa.Integer(), sa.ForeignKey("backup_snapshots.id"), nullable=False),
        sa.Column("chunk_hash", sa.String(64), nullable=False, index=True),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("entropy", sa.Float(), default=0.0),
        sa.Column("is_new", sa.Boolean(), default=True),
    )

    op.create_table(
        "snapshot_files",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("snapshot_id", sa.Integer(), sa.ForeignKey("backup_snapshots.id", ondelete="CASCADE"), nullable=False),
        sa.Column("file_path", sa.Text(), nullable=False),
        sa.Column("file_size", sa.BigInteger(), default=0),
        sa.Column("chunk_hashes", sa.Text(), nullable=False),
    )
    op.create_index("ix_snapshot_files_snapshot_id", "snapshot_files", ["snapshot_id"])

    op.create_table(
        "restore_jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("data_sources.id"), nullable=False),
        sa.Column("snapshot_id", sa.Integer(), sa.ForeignKey("backup_snapshots.id"), nullable=False),
        sa.Column("celery_task_id", sa.String(255), nullable=True),
        sa.Column("status", sa.String(50), nullable=False),
        sa.Column("restore_path", sa.Text(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "anomaly_alerts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source_id", sa.Integer(), sa.ForeignKey("data_sources.id"), nullable=False),
        sa.Column("alert_type", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(50), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("metric_value", sa.Float(), nullable=True),
        sa.Column("threshold_value", sa.Float(), nullable=True),
        sa.Column("resolved", sa.Boolean(), default=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_anomaly_alerts_source_id", "anomaly_alerts", ["source_id"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("resource_type", sa.String(100), nullable=True),
        sa.Column("resource_id", sa.String(100), nullable=True),
        sa.Column("actor", sa.String(255), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_logs_tenant_id", "audit_logs", ["tenant_id"])


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("anomaly_alerts")
    op.drop_table("restore_jobs")
    op.drop_table("snapshot_files")
    op.drop_table("backup_chunks")
    op.drop_table("backup_snapshots")
    op.drop_table("backup_jobs")
    op.drop_table("policy_attachments")
    op.drop_table("backup_policies")
    op.drop_table("data_sources")
    op.drop_table("tenants")
