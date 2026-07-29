"""
APScheduler configuration for periodic policy evaluation and retention enforcement.

Two jobs run inside the FastAPI process:

  policy_evaluator  (every 5 min)
    For each source with an active policy:
      1. Skip if a backup job is already pending / running (dedup guard)
      2. Dispatch a new backup job if the last completed one is overdue
      3. Raise an RPO violation alert if the gap exceeds policy.rpo_minutes
      4. Raise a backup-gap alert if the gap exceeds 3× the frequency window

  retention_pruner  (every 60 min)
    For each source with an active policy:
      1. Find snapshots older than policy.retention_days
      2. Delete them (cascades to BackupChunk / SnapshotFile via ORM)
      3. GC CAS chunks that are no longer referenced by any remaining snapshot
      4. Always keep at least the most-recent snapshot regardless of age
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings

logger = logging.getLogger(__name__)
scheduler = AsyncIOScheduler()

# ---------------------------------------------------------------------------
# Lazy engine for the scheduler (separate from the FastAPI engine so the
# scheduler can have its own connection pool).
# ---------------------------------------------------------------------------
_sched_engine = None
_sched_session_factory = None


def _get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _sched_engine, _sched_session_factory
    if _sched_session_factory is None:
        _sched_engine = create_async_engine(settings.database_url, echo=False)
        _sched_session_factory = async_sessionmaker(_sched_engine, expire_on_commit=False)
    return _sched_session_factory


# ---------------------------------------------------------------------------
# Policy evaluation job
# ---------------------------------------------------------------------------


async def evaluate_all_policies() -> None:
    """Triggered every 5 minutes by APScheduler."""
    from app.models.anomaly import AlertSeverity, AlertType, AnomalyAlert
    from app.models.backup import BackupJob, BackupSnapshot, JobStatus
    from app.models.policy import BackupPolicy, PolicyAttachment
    from app.models.source import DataSource

    SessionFactory = _get_session_factory()
    now = datetime.now(timezone.utc)

    try:
        async with SessionFactory() as db:
            stmt = (
                select(PolicyAttachment, BackupPolicy, DataSource)
                .join(BackupPolicy, PolicyAttachment.policy_id == BackupPolicy.id)
                .join(DataSource, PolicyAttachment.source_id == DataSource.id)
                .where(BackupPolicy.is_active == True)
            )
            rows = (await db.execute(stmt)).all()

            for attachment, policy, source in rows:
                # --------------------------------------------------------
                # Dedup guard: skip if a job is already in flight
                # --------------------------------------------------------
                active_stmt = (
                    select(BackupJob.id)
                    .where(
                        BackupJob.source_id == source.id,
                        BackupJob.status.in_([JobStatus.pending, JobStatus.running]),
                    )
                    .limit(1)
                )
                active_job_id = (await db.execute(active_stmt)).scalar_one_or_none()
                if active_job_id is not None:
                    logger.debug(
                        "Skipping dispatch for source %d — job %d already active",
                        source.id,
                        active_job_id,
                    )
                    continue

                # Find last completed backup job for this source
                last_job_stmt = (
                    select(BackupJob)
                    .where(
                        BackupJob.source_id == source.id,
                        BackupJob.status == JobStatus.completed,
                    )
                    .order_by(BackupJob.completed_at.desc())
                    .limit(1)
                )
                last_job = (await db.execute(last_job_stmt)).scalar_one_or_none()

                if last_job is None:
                    await _dispatch_backup(db, source.id, source.path, "full")
                    continue

                completed_at = last_job.completed_at
                if completed_at.tzinfo is None:
                    completed_at = completed_at.replace(tzinfo=timezone.utc)

                elapsed_minutes = (now - completed_at).total_seconds() / 60

                if elapsed_minutes >= policy.frequency_minutes:
                    logger.info(
                        "Dispatching scheduled backup for source %d (overdue by %.1f min)",
                        source.id,
                        elapsed_minutes - policy.frequency_minutes,
                    )
                    await _dispatch_backup(db, source.id, source.path, "incremental")

                if elapsed_minutes > policy.rpo_minutes:
                    logger.warning(
                        "RPO violation for source %d: %.1f min since last backup (limit %d min)",
                        source.id,
                        elapsed_minutes,
                        policy.rpo_minutes,
                    )
                    alert = AnomalyAlert(
                        source_id=source.id,
                        alert_type=AlertType.rpo_violation,
                        severity=AlertSeverity.high,
                        detail=(
                            f"RPO violated: {elapsed_minutes:.1f} minutes since last completed "
                            f"backup exceeds policy limit of {policy.rpo_minutes} minutes."
                        ),
                        metric_value=elapsed_minutes,
                        threshold_value=float(policy.rpo_minutes),
                    )
                    db.add(alert)

                if elapsed_minutes > 3 * policy.frequency_minutes:
                    gap_alert = AnomalyAlert(
                        source_id=source.id,
                        alert_type=AlertType.backup_gap,
                        severity=AlertSeverity.critical,
                        detail=(
                            f"Backup gap detected: {elapsed_minutes:.1f} minutes since last backup "
                            f"exceeds 3× the policy frequency ({policy.frequency_minutes} min)."
                        ),
                        metric_value=elapsed_minutes,
                        threshold_value=float(3 * policy.frequency_minutes),
                    )
                    db.add(gap_alert)

            await db.commit()
    except Exception:
        logger.exception("Error in evaluate_all_policies")


# ---------------------------------------------------------------------------
# Retention / GC job
# ---------------------------------------------------------------------------


async def prune_expired_snapshots() -> None:
    """
    Triggered every 60 minutes by APScheduler.

    Deletes snapshots older than the source's policy retention_days, then
    garbage-collects CAS chunks that are no longer referenced by any snapshot.
    The most-recent snapshot for each source is always kept regardless of age.
    """
    from app.models.backup import BackupChunk, BackupSnapshot
    from app.models.policy import BackupPolicy, PolicyAttachment
    from app.models.source import DataSource

    SessionFactory = _get_session_factory()
    now = datetime.now(timezone.utc)

    try:
        async with SessionFactory() as db:
            stmt = (
                select(PolicyAttachment, BackupPolicy, DataSource)
                .join(BackupPolicy, PolicyAttachment.policy_id == BackupPolicy.id)
                .join(DataSource, PolicyAttachment.source_id == DataSource.id)
                .where(BackupPolicy.is_active == True)
            )
            rows = (await db.execute(stmt)).all()

            pruned_total = 0
            for attachment, policy, source in rows:
                retention_cutoff = now - timedelta(days=policy.retention_days)

                # Most-recent snapshot — never prune this one
                most_recent_stmt = (
                    select(BackupSnapshot.id)
                    .where(BackupSnapshot.source_id == source.id)
                    .order_by(BackupSnapshot.created_at.desc())
                    .limit(1)
                )
                most_recent_id = (await db.execute(most_recent_stmt)).scalar_one_or_none()

                expired_stmt = (
                    select(BackupSnapshot)
                    .where(
                        BackupSnapshot.source_id == source.id,
                        BackupSnapshot.created_at < retention_cutoff,
                    )
                    .order_by(BackupSnapshot.created_at.asc())
                )
                expired_snapshots = (await db.execute(expired_stmt)).scalars().all()

                for snapshot in expired_snapshots:
                    if snapshot.id == most_recent_id:
                        continue

                    # Respect WORM immutable lock
                    if snapshot.locked_until and snapshot.locked_until > now:
                        logger.debug(
                            "Skipping locked snapshot %d (locked until %s)",
                            snapshot.id,
                            snapshot.locked_until.isoformat(),
                        )
                        continue

                    # Collect chunk hashes before cascade-delete removes them
                    chunk_hashes_stmt = select(BackupChunk.chunk_hash).where(
                        BackupChunk.snapshot_id == snapshot.id
                    )
                    chunk_hashes = list(
                        (await db.execute(chunk_hashes_stmt)).scalars().all()
                    )

                    # Delete snapshot (ORM cascade removes BackupChunk + SnapshotFile)
                    await db.delete(snapshot)
                    await db.flush()

                    # GC: delete CAS chunks with no remaining DB references
                    from app.core.cas import CASStore

                    cas_store = CASStore(settings.cas_store_path)
                    for chunk_hash in chunk_hashes:
                        still_ref_stmt = (
                            select(BackupChunk.id)
                            .where(BackupChunk.chunk_hash == chunk_hash)
                            .limit(1)
                        )
                        if (await db.execute(still_ref_stmt)).scalar_one_or_none() is None:
                            cas_store.delete(chunk_hash)

                    pruned_total += 1

            await db.commit()
            if pruned_total:
                logger.info("Retention pruner: removed %d expired snapshots", pruned_total)
    except Exception:
        logger.exception("Error in prune_expired_snapshots")


# ---------------------------------------------------------------------------
# Automated recovery verification job
# ---------------------------------------------------------------------------


async def verify_snapshot_integrity() -> None:
    """
    Triggered daily by APScheduler.

    Finds snapshots that have never been verified, or were last verified more
    than 7 days ago, and recomputes their Merkle root from SnapshotFile
    manifests.  Any mismatch is logged as a WARNING and recorded in
    verification_status so operators can act on it.

    Up to 100 snapshots are processed per run to keep the job bounded.
    """
    from app.models.backup import BackupSnapshot, SnapshotFile
    from app.models.source import DataSource

    SessionFactory = _get_session_factory()
    now = datetime.now(timezone.utc)
    verify_cutoff = now - timedelta(days=7)

    try:
        async with SessionFactory() as db:
            stmt = (
                select(BackupSnapshot)
                .join(DataSource, BackupSnapshot.source_id == DataSource.id)
                .where(
                    (BackupSnapshot.last_verified_at == None)  # noqa: E711
                    | (BackupSnapshot.last_verified_at < verify_cutoff)
                )
                .order_by(BackupSnapshot.created_at.desc())
                .limit(100)
            )
            snapshots = (await db.execute(stmt)).scalars().all()

            verified = 0
            failed = 0
            for snapshot in snapshots:
                sf_result = await db.execute(
                    select(SnapshotFile)
                    .where(SnapshotFile.snapshot_id == snapshot.id)
                    .order_by(SnapshotFile.id)
                )
                sf_records = sf_result.scalars().all()
                if not sf_records:
                    continue  # skip pre-SnapshotFile legacy snapshots

                from app.core.merkle import MerkleTree

                chunk_hashes = [h for sf in sf_records for h in sf.get_chunk_hashes()]
                computed_root = MerkleTree(chunk_hashes).root_hash
                is_valid = computed_root == snapshot.merkle_root

                snapshot.last_verified_at = now
                snapshot.verification_status = "passed" if is_valid else "failed"

                if is_valid:
                    verified += 1
                else:
                    failed += 1
                    logger.warning(
                        "Integrity check FAILED for snapshot %d (source %d): "
                        "stored=%s computed=%s",
                        snapshot.id,
                        snapshot.source_id,
                        snapshot.merkle_root,
                        computed_root,
                    )

            await db.commit()
            logger.info(
                "Snapshot integrity verification: %d passed, %d failed",
                verified,
                failed,
            )
    except Exception:
        logger.exception("Error in verify_snapshot_integrity")


# ---------------------------------------------------------------------------
# Dispatch helper
# ---------------------------------------------------------------------------


async def _dispatch_backup(
    db: AsyncSession,
    source_id: int,
    source_path: str,
    backup_type: str,
) -> None:
    """
    Create a BackupJob record, then dispatch the Celery task.
    Creating the job first ensures the FK constraint on backup_snapshots
    is satisfied when the worker writes its snapshot record.
    """
    from app.models.backup import BackupJob, BackupType, JobStatus

    job = BackupJob(
        source_id=source_id,
        backup_type=BackupType(backup_type),
        status=JobStatus.pending,
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    try:
        from app.workers.backup_worker import run_backup

        task = run_backup.delay(job.id, source_path, source_id, backup_type)
        job.celery_task_id = task.id
        await db.commit()
    except Exception:
        logger.exception("Failed to dispatch backup for source %d", source_id)
        job.status = JobStatus.failed
        job.error_message = "Celery broker unavailable"
        await db.commit()


# ---------------------------------------------------------------------------
# Start / stop helpers
# ---------------------------------------------------------------------------


def start_scheduler() -> None:
    scheduler.add_job(
        evaluate_all_policies,
        IntervalTrigger(minutes=5),
        id="policy_evaluator",
        replace_existing=True,
    )
    scheduler.add_job(
        prune_expired_snapshots,
        IntervalTrigger(minutes=60),
        id="retention_pruner",
        replace_existing=True,
    )
    scheduler.add_job(
        verify_snapshot_integrity,
        IntervalTrigger(days=1),
        id="integrity_verifier",
        replace_existing=True,
    )
    scheduler.start()
    logger.info(
        "APScheduler started — policy evaluation every 5 min, "
        "retention pruning every 60 min, integrity verification daily"
    )


def stop_scheduler() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("APScheduler stopped")
