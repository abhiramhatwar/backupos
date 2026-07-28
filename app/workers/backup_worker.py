"""
Celery task: run_backup

Uses synchronous SQLAlchemy (psycopg2) because Celery workers do not have
an asyncio event loop running.
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

from celery.exceptions import MaxRetriesExceededError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.cas import CASStore
from app.core.cdc import CDCChunker
from app.core.config import settings
from app.core.entropy import entropy_spike_detected
from app.core.merkle import MerkleTree
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Synchronous SQLAlchemy engine for Celery workers
# ---------------------------------------------------------------------------
_sync_url = settings.database_url.replace("+asyncpg", "")
_engine = create_engine(_sync_url, pool_pre_ping=True)
SyncSession: sessionmaker[Session] = sessionmaker(_engine, expire_on_commit=False)

# ---------------------------------------------------------------------------
# CAS store singleton
# ---------------------------------------------------------------------------
cas = CASStore(settings.cas_store_path)
chunker = CDCChunker()


# ---------------------------------------------------------------------------
# Helper: update job status
# ---------------------------------------------------------------------------

def _update_job(db: Session, job_id: int, **kwargs) -> None:
    from app.models.backup import BackupJob
    job = db.get(BackupJob, job_id)
    if job is None:
        return
    for k, v in kwargs.items():
        setattr(job, k, v)
    db.commit()


# ---------------------------------------------------------------------------
# Main task
# ---------------------------------------------------------------------------

@celery_app.task(bind=True, max_retries=3, default_retry_delay=60)
def run_backup(self, job_id: int, source_path: str, source_id: int, backup_type: str):
    """
    Execute a backup job end-to-end:

    1. Mark job RUNNING
    2. Chunk all files under source_path with CDC
    3. Store each chunk in CAS (deduplication is automatic)
    4. Build MerkleTree; diff against previous snapshot for incremental
    5. Persist BackupSnapshot + BackupChunk records
    6. Run anomaly detection (entropy spike, size anomaly)
    7. Mark job COMPLETED
    """
    from app.models.anomaly import AlertSeverity, AlertType, AnomalyAlert
    from app.models.backup import (
        BackupChunk,
        BackupJob,
        BackupSnapshot,
        BackupType,
        JobStatus,
    )
    from app.models.policy import BackupPolicy, PolicyAttachment

    with SyncSession() as db:
        # ------------------------------------------------------------------
        # 1. Mark job as RUNNING
        # ------------------------------------------------------------------
        job = db.get(BackupJob, job_id)
        if job is None and job_id != 0:
            logger.error("BackupJob %d not found", job_id)
            return

        if job is not None:
            job.status = JobStatus.running
            job.started_at = datetime.now(timezone.utc)
            db.commit()

        try:
            # ------------------------------------------------------------------
            # 2. Collect all files under source_path
            # ------------------------------------------------------------------
            all_chunks: list[bytes] = []
            if os.path.isfile(source_path):
                all_chunks = chunker.chunk_data(open(source_path, "rb").read())
            elif os.path.isdir(source_path):
                for root, _dirs, files in os.walk(source_path):
                    for fname in sorted(files):
                        fpath = os.path.join(root, fname)
                        try:
                            with open(fpath, "rb") as f:
                                data = f.read()
                            all_chunks.extend(chunker.chunk_data(data))
                        except OSError as exc:
                            logger.warning("Skipping %s: %s", fpath, exc)
            else:
                logger.warning("source_path %s does not exist; creating empty snapshot", source_path)

            # ------------------------------------------------------------------
            # 3. Store chunks in CAS — compute per-chunk entropy in the same pass
            # ------------------------------------------------------------------
            chunk_hashes: list[str] = []
            chunk_sizes: list[int] = []
            chunk_is_new: list[bool] = []
            chunk_entropies: list[float] = []

            from app.core.entropy import shannon_entropy as _entropy
            for chunk in all_chunks:
                digest, is_new = cas.store(chunk)
                chunk_hashes.append(digest)
                chunk_sizes.append(len(chunk))
                chunk_is_new.append(is_new)
                chunk_entropies.append(_entropy(chunk))

            # ------------------------------------------------------------------
            # 4. Build Merkle tree
            # ------------------------------------------------------------------
            tree = MerkleTree(chunk_hashes)

            # Get previous snapshot for this source (for incremental diff)
            prev_snapshot = None
            if backup_type == BackupType.incremental or backup_type == "incremental":
                prev_stmt = (
                    select(BackupSnapshot)
                    .where(BackupSnapshot.source_id == source_id)
                    .order_by(BackupSnapshot.created_at.desc())
                    .limit(1)
                )
                prev_snapshot = db.execute(prev_stmt).scalar_one_or_none()

            new_hashes: set[str] = set()
            if prev_snapshot is not None:
                prev_hashes_stmt = select(BackupChunk.chunk_hash).where(
                    BackupChunk.snapshot_id == prev_snapshot.id
                )
                prev_hash_rows = db.execute(prev_hashes_stmt).scalars().all()
                prev_tree = MerkleTree(list(prev_hash_rows))
                new_hashes = set(tree.diff(prev_tree))
            else:
                new_hashes = set(chunk_hashes)

            # ------------------------------------------------------------------
            # 5. Entropy analysis — reuse per-chunk values already computed
            # ------------------------------------------------------------------
            avg_entropy = (sum(chunk_entropies) / len(chunk_entropies)) if chunk_entropies else 0.0

            # ------------------------------------------------------------------
            # 6. Persist BackupSnapshot
            # ------------------------------------------------------------------
            total_size = sum(chunk_sizes)
            dedup_size = sum(s for s, is_new in zip(chunk_sizes, chunk_is_new) if is_new)
            new_count = sum(1 for h in chunk_hashes if h in new_hashes)

            snapshot = BackupSnapshot(
                job_id=job_id if job_id != 0 else 0,
                source_id=source_id,
                merkle_root=tree.root_hash,
                parent_snapshot_id=prev_snapshot.id if prev_snapshot else None,
                total_size_bytes=total_size,
                dedup_size_bytes=dedup_size,
                chunk_count=len(chunk_hashes),
                new_chunk_count=new_count,
                average_entropy=avg_entropy,
            )
            db.add(snapshot)
            db.flush()  # assign snapshot.id

            # Persist chunk records
            for digest, size, entropy_val, is_new_chunk in zip(
                chunk_hashes,
                chunk_sizes,
                chunk_entropies,
                chunk_is_new,
            ):
                chunk_rec = BackupChunk(
                    snapshot_id=snapshot.id,
                    chunk_hash=digest,
                    size_bytes=size,
                    entropy=entropy_val,
                    is_new=digest in new_hashes,
                )
                db.add(chunk_rec)

            db.commit()

            # ------------------------------------------------------------------
            # 7. Anomaly detection
            # ------------------------------------------------------------------
            # Entropy spike
            prev_avg_entropy = 0.0
            if prev_snapshot is not None:
                prev_avg_entropy = prev_snapshot.average_entropy or 0.0

            policy_threshold = 7.5
            try:
                policy_stmt = (
                    select(BackupPolicy)
                    .join(
                        PolicyAttachment,
                        PolicyAttachment.policy_id == BackupPolicy.id,
                    )
                    .where(PolicyAttachment.source_id == source_id)
                    .limit(1)
                )
                policy = db.execute(policy_stmt).scalar_one_or_none()
                if policy:
                    policy_threshold = policy.entropy_threshold
            except Exception:
                pass

            if avg_entropy > policy_threshold or entropy_spike_detected(avg_entropy, prev_avg_entropy):
                alert = AnomalyAlert(
                    source_id=source_id,
                    alert_type=AlertType.entropy_spike,
                    severity=AlertSeverity.high,
                    detail=(
                        f"High entropy detected: avg={avg_entropy:.3f} bits/byte "
                        f"(threshold={policy_threshold}). Possible ransomware activity."
                    ),
                    metric_value=avg_entropy,
                    threshold_value=policy_threshold,
                )
                db.add(alert)

            # Size anomaly — compare to rolling average of last 5 snapshots
            recent_stmt = (
                select(BackupSnapshot)
                .where(BackupSnapshot.source_id == source_id)
                .order_by(BackupSnapshot.created_at.desc())
                .limit(5)
            )
            recent = db.execute(recent_stmt).scalars().all()
            if len(recent) >= 2:
                sizes = [s.total_size_bytes for s in recent if s.id != snapshot.id]
                if sizes:
                    rolling_avg = sum(sizes) / len(sizes)
                    if rolling_avg > 0 and total_size > 3 * rolling_avg:
                        size_alert = AnomalyAlert(
                            source_id=source_id,
                            alert_type=AlertType.size_anomaly,
                            severity=AlertSeverity.high,
                            detail=(
                                f"Backup size anomaly: current={total_size} bytes is "
                                f"{total_size/rolling_avg:.1f}x the rolling average ({rolling_avg:.0f} bytes)."
                            ),
                            metric_value=float(total_size),
                            threshold_value=rolling_avg * 3,
                        )
                        db.add(size_alert)

            db.commit()

            # ------------------------------------------------------------------
            # 8. Mark job COMPLETED
            # ------------------------------------------------------------------
            if job is not None:
                job = db.get(BackupJob, job_id)
                if job:
                    job.status = JobStatus.completed
                    job.completed_at = datetime.now(timezone.utc)
                    db.commit()

            logger.info(
                "Backup job %d completed: %d chunks, %d new, merkle=%s",
                job_id,
                len(chunk_hashes),
                new_count,
                tree.root_hash[:12],
            )

        except Exception as exc:
            logger.exception("Backup job %d failed: %s", job_id, exc)
            if job is not None:
                job = db.get(BackupJob, job_id)
                if job:
                    job.status = JobStatus.failed
                    job.error_message = str(exc)
                    db.commit()
            try:
                raise self.retry(exc=exc)
            except MaxRetriesExceededError:
                logger.error("Backup job %d exceeded max retries", job_id)
