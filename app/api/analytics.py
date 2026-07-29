"""
Storage analytics and capacity growth projection.

GET /api/v1/analytics/sources/{source_id}
  Returns per-snapshot dedup/compression trends and a linear-regression
  growth projection so operators can plan capacity before they run out.

The growth projection models deduplicated storage growth (actual bytes stored
on disk after dedup) over time using ordinary least squares.  r_squared
indicates how linear the growth trend is; values above 0.85 make the
30-day and 90-day projections reliable.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_tenant
from app.core.database import get_db
from app.models.backup import BackupChunk, BackupSnapshot
from app.models.source import DataSource
from app.models.tenant import Tenant

router = APIRouter()


class SnapshotTrend(BaseModel):
    snapshot_id: int
    created_at: object
    total_size_bytes: int
    dedup_size_bytes: int
    dedup_ratio: float
    new_chunk_count: int
    chunk_count: int
    average_entropy: float


class GrowthProjection(BaseModel):
    slope_bytes_per_day: float
    projected_30d_bytes: int
    projected_90d_bytes: int
    r_squared: float
    data_points: int


class AnalyticsResponse(BaseModel):
    source_id: int
    snapshot_count: int
    total_unique_bytes: int
    total_raw_bytes: int
    overall_dedup_ratio: float
    compression_savings_bytes: int
    trends: list[SnapshotTrend]
    growth_projection: Optional[GrowthProjection]


def _ols(xs: list[float], ys: list[float]) -> tuple[float, float, float]:
    """Ordinary least squares: returns (slope, intercept, r_squared)."""
    n = len(xs)
    if n < 2:
        return 0.0, ys[0] if ys else 0.0, 0.0
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    ss_xy = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    ss_xx = sum((x - mean_x) ** 2 for x in xs)
    if ss_xx == 0:
        return 0.0, mean_y, 1.0
    slope = ss_xy / ss_xx
    intercept = mean_y - slope * mean_x
    ss_res = sum((y - (slope * x + intercept)) ** 2 for x, y in zip(xs, ys))
    ss_tot = sum((y - mean_y) ** 2 for y in ys)
    r_sq = 1.0 - ss_res / ss_tot if ss_tot > 0 else 1.0
    return slope, intercept, r_sq


@router.get("/sources/{source_id}", response_model=AnalyticsResponse)
async def source_analytics(
    source_id: int,
    tenant: Tenant = Depends(get_current_tenant),
    db: AsyncSession = Depends(get_db),
):
    source_result = await db.execute(
        select(DataSource).where(
            DataSource.id == source_id,
            DataSource.tenant_id == tenant.id,
        )
    )
    if not source_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Data source not found")

    snaps_result = await db.execute(
        select(BackupSnapshot)
        .where(BackupSnapshot.source_id == source_id)
        .order_by(BackupSnapshot.created_at.asc())
    )
    snapshots = snaps_result.scalars().all()

    if not snapshots:
        return AnalyticsResponse(
            source_id=source_id,
            snapshot_count=0,
            total_unique_bytes=0,
            total_raw_bytes=0,
            overall_dedup_ratio=0.0,
            compression_savings_bytes=0,
            trends=[],
            growth_projection=None,
        )

    # Compression savings from chunk-level records
    chunks_result = await db.execute(
        select(BackupChunk)
        .join(BackupSnapshot, BackupChunk.snapshot_id == BackupSnapshot.id)
        .where(BackupSnapshot.source_id == source_id)
    )
    chunks = chunks_result.scalars().all()
    compression_savings = sum(
        c.size_bytes - c.compressed_size_bytes
        for c in chunks
        if c.compressed_size_bytes is not None and c.size_bytes > c.compressed_size_bytes
    )

    total_raw = sum(s.total_size_bytes for s in snapshots)
    overall_dedup_ratio = 0.0
    if total_raw > 0:
        total_dedup = sum(s.dedup_size_bytes for s in snapshots)
        overall_dedup_ratio = round((total_raw - total_dedup) / total_raw, 4)

    trends = []
    for s in snapshots:
        ratio = 0.0
        if s.total_size_bytes > 0:
            ratio = round((s.total_size_bytes - s.dedup_size_bytes) / s.total_size_bytes, 4)
        trends.append(SnapshotTrend(
            snapshot_id=s.id,
            created_at=s.created_at,
            total_size_bytes=s.total_size_bytes,
            dedup_size_bytes=s.dedup_size_bytes,
            dedup_ratio=ratio,
            new_chunk_count=s.new_chunk_count,
            chunk_count=s.chunk_count,
            average_entropy=s.average_entropy,
        ))

    growth_projection = None
    if len(snapshots) >= 2:
        base_ts = snapshots[0].created_at.timestamp()
        xs = [(s.created_at.timestamp() - base_ts) / 86400.0 for s in snapshots]
        ys = [float(s.dedup_size_bytes) for s in snapshots]
        slope, _, r_sq = _ols(xs, ys)
        last_y = ys[-1]
        growth_projection = GrowthProjection(
            slope_bytes_per_day=round(slope, 2),
            projected_30d_bytes=max(0, int(last_y + slope * 30)),
            projected_90d_bytes=max(0, int(last_y + slope * 90)),
            r_squared=round(r_sq, 4),
            data_points=len(snapshots),
        )

    return AnalyticsResponse(
        source_id=source_id,
        snapshot_count=len(snapshots),
        total_unique_bytes=snapshots[-1].dedup_size_bytes,
        total_raw_bytes=total_raw,
        overall_dedup_ratio=overall_dedup_ratio,
        compression_savings_bytes=compression_savings,
        trends=trends,
        growth_projection=growth_projection,
    )
