"""Performance indexes and compressed_size_bytes column

Revision ID: 002
Revises: 001
Create Date: 2024-01-02 00:00:00.000000

Adds:
  * backup_snapshots composite index on (source_id, created_at DESC) — the
    "last N snapshots for source" query pattern used by backup worker, scheduler,
    and recovery-metrics endpoint
  * anomaly_alerts composite index on (source_id, resolved) — the open-alerts
    query used by the anomaly dashboard
  * backup_chunks index on snapshot_id — avoids full-table scans when loading
    all chunks for a snapshot during verify / restore
  * backup_chunks.compressed_size_bytes column — tracks on-disk (post-zstd)
    chunk size for compression ratio reporting
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Composite index: latest N snapshots for a source (used heavily by scheduler
    # and backup worker for incremental diff and EWMA baseline queries)
    op.create_index(
        "ix_backup_snapshots_source_created",
        "backup_snapshots",
        ["source_id", sa.text("created_at DESC")],
    )

    # Composite index: unresolved alerts per source (anomaly dashboard hot path)
    op.create_index(
        "ix_anomaly_alerts_source_resolved",
        "anomaly_alerts",
        ["source_id", "resolved"],
    )

    # Index: all chunks belonging to a snapshot (verify + restore hot path)
    op.create_index(
        "ix_backup_chunks_snapshot_id",
        "backup_chunks",
        ["snapshot_id"],
    )

    # New column: on-disk (compressed) size for compression ratio reporting
    op.add_column(
        "backup_chunks",
        sa.Column("compressed_size_bytes", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("backup_chunks", "compressed_size_bytes")
    op.drop_index("ix_backup_chunks_snapshot_id", table_name="backup_chunks")
    op.drop_index("ix_anomaly_alerts_source_resolved", table_name="anomaly_alerts")
    op.drop_index("ix_backup_snapshots_source_created", table_name="backup_snapshots")
