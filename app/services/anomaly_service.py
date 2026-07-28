"""
Anomaly detection service.

Checks backup snapshots for entropy spikes (possible ransomware) and
unexpected size growth.  Creates AnomalyAlert records when anomalies are
found.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.entropy import entropy_spike_detected


async def check_entropy_anomaly(
    db: AsyncSession,
    source_id: int,
    snapshot,
    policy,
) -> None:
    """
    Compare *snapshot.average_entropy* to the previous snapshot for the same
    source.  If a spike is detected and entropy exceeds the policy threshold,
    create an AnomalyAlert.

    Parameters
    ----------
    db          : async SQLAlchemy session
    source_id   : DataSource.id
    snapshot    : BackupSnapshot ORM object (just persisted)
    policy      : BackupPolicy ORM object (or None)
    """
    from app.models.anomaly import AlertSeverity, AlertType, AnomalyAlert
    from app.models.backup import BackupSnapshot

    threshold = policy.entropy_threshold if policy else 7.5
    current_avg = snapshot.average_entropy or 0.0

    # Fetch the previous snapshot
    prev_stmt = (
        select(BackupSnapshot)
        .where(
            BackupSnapshot.source_id == source_id,
            BackupSnapshot.id != snapshot.id,
        )
        .order_by(BackupSnapshot.created_at.desc())
        .limit(1)
    )
    prev = (await db.execute(prev_stmt)).scalar_one_or_none()
    prev_avg = prev.average_entropy if prev else 0.0

    is_spike = entropy_spike_detected(current_avg, prev_avg, threshold=threshold)
    is_above_threshold = current_avg > threshold

    if is_spike or is_above_threshold:
        alert = AnomalyAlert(
            source_id=source_id,
            alert_type=AlertType.entropy_spike,
            severity=AlertSeverity.high,
            detail=(
                f"Entropy anomaly: current avg={current_avg:.3f} bits/byte "
                f"(threshold={threshold}, previous={prev_avg:.3f}). "
                "Possible ransomware or unexpected encryption."
            ),
            metric_value=current_avg,
            threshold_value=threshold,
        )
        db.add(alert)
        await db.commit()


async def check_size_anomaly(
    db: AsyncSession,
    source_id: int,
    snapshot,
) -> None:
    """
    Compare *snapshot.total_size_bytes* to the rolling average of the last 5
    snapshots for this source.  If the current snapshot is more than 3x the
    average, create a size_anomaly AnomalyAlert.

    Parameters
    ----------
    db          : async SQLAlchemy session
    source_id   : DataSource.id
    snapshot    : BackupSnapshot ORM object (just persisted)
    """
    from app.models.anomaly import AlertSeverity, AlertType, AnomalyAlert
    from app.models.backup import BackupSnapshot

    recent_stmt = (
        select(BackupSnapshot)
        .where(
            BackupSnapshot.source_id == source_id,
            BackupSnapshot.id != snapshot.id,
        )
        .order_by(BackupSnapshot.created_at.desc())
        .limit(5)
    )
    recent = (await db.execute(recent_stmt)).scalars().all()

    if not recent:
        return  # No historical data to compare against

    sizes = [s.total_size_bytes for s in recent if s.total_size_bytes > 0]
    if not sizes:
        return

    rolling_avg = sum(sizes) / len(sizes)
    current = snapshot.total_size_bytes or 0

    if rolling_avg > 0 and current > 3 * rolling_avg:
        alert = AnomalyAlert(
            source_id=source_id,
            alert_type=AlertType.size_anomaly,
            severity=AlertSeverity.high,
            detail=(
                f"Backup size anomaly: {current} bytes is "
                f"{current / rolling_avg:.1f}x the rolling average "
                f"({rolling_avg:.0f} bytes over last {len(sizes)} snapshots)."
            ),
            metric_value=float(current),
            threshold_value=rolling_avg * 3,
        )
        db.add(alert)
        await db.commit()
