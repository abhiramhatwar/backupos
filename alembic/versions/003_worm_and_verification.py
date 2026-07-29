"""WORM lock and automated recovery verification columns

Revision ID: 003
Revises: 002
Create Date: 2024-01-03 00:00:00.000000

Adds to backup_snapshots:
  * locked_until   — WORM immutable lock expiry timestamp; pruner skips locked rows
  * last_verified_at — timestamp of last automated integrity verification run
  * verification_status — "passed" | "failed" | NULL (never verified)
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "backup_snapshots",
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "backup_snapshots",
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "backup_snapshots",
        sa.Column("verification_status", sa.String(20), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("backup_snapshots", "verification_status")
    op.drop_column("backup_snapshots", "last_verified_at")
    op.drop_column("backup_snapshots", "locked_until")
