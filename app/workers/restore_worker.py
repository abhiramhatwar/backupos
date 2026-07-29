"""
Celery task: run_restore

Reconstructs a backed-up dataset from CAS chunks using the per-file chunk
manifests stored in SnapshotFile records.  Files are written to their original
relative paths under restore_path, restoring the full directory tree rather
than a single flat blob.

An optional file_path parameter restricts the restore to a single file within
the snapshot, enabling granular file-level recovery without touching the rest
of the snapshot.

Job states:  PENDING → RUNNING → VERIFYING → COMPLETED / FAILED
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

from celery.exceptions import MaxRetriesExceededError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.cas import CASStore
from app.core.config import settings
from app.core.merkle import MerkleTree
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

_sync_url = settings.database_url.replace("+asyncpg", "")
_engine = create_engine(_sync_url, pool_pre_ping=True)
SyncSession: sessionmaker[Session] = sessionmaker(_engine, expire_on_commit=False)

cas = CASStore(settings.cas_store_path)


@celery_app.task(bind=True, max_retries=3, default_retry_delay=60)
def run_restore(
    self,
    job_id: int,
    snapshot_id: int,
    restore_path: str,
    file_path: str | None = None,
):
    """
    Restore a snapshot (or a single file within it):

    1. Load BackupSnapshot + SnapshotFile records (file→chunk manifests)
    2. If file_path is given, restore only that file; otherwise restore all files
    3. Fall back to flat blob restore when no SnapshotFile records exist
    4. Set status to VERIFYING, then recompute Merkle root and compare
    5. Mark job COMPLETED / FAILED
    """
    from app.models.backup import BackupChunk, BackupSnapshot, JobStatus, SnapshotFile
    from app.models.restore_job import RestoreJob

    with SyncSession() as db:
        job = db.get(RestoreJob, job_id)
        if job is None:
            logger.error("RestoreJob %d not found", job_id)
            return

        job.status = JobStatus.running
        job.started_at = datetime.now(timezone.utc)
        db.commit()

        try:
            snapshot = db.get(BackupSnapshot, snapshot_id)
            if snapshot is None:
                raise ValueError(f"BackupSnapshot {snapshot_id} not found")

            os.makedirs(restore_path, exist_ok=True)

            # ------------------------------------------------------------------
            # Load per-file manifests
            # ------------------------------------------------------------------
            file_records_stmt = (
                select(SnapshotFile)
                .where(SnapshotFile.snapshot_id == snapshot_id)
                .order_by(SnapshotFile.id)
            )
            file_records = db.execute(file_records_stmt).scalars().all()

            # If a specific file was requested, filter to just that record
            if file_path is not None and file_records:
                file_records = [f for f in file_records if f.file_path == file_path]
                if not file_records:
                    raise ValueError(
                        f"File '{file_path}' not found in snapshot {snapshot_id}"
                    )

            restored_hashes: list[str] = []

            if file_records:
                for file_rec in file_records:
                    hashes = file_rec.get_chunk_hashes()
                    out_path = os.path.join(restore_path, file_rec.file_path)
                    os.makedirs(os.path.dirname(out_path) or restore_path, exist_ok=True)
                    with open(out_path, "wb") as fh:
                        for h in hashes:
                            fh.write(cas.retrieve(h))
                    restored_hashes.extend(hashes)
            else:
                # Legacy fallback: reassemble as a single blob in chunk-insertion order
                chunks_stmt = (
                    select(BackupChunk)
                    .where(BackupChunk.snapshot_id == snapshot_id)
                    .order_by(BackupChunk.id)
                )
                chunk_records = db.execute(chunks_stmt).scalars().all()
                output_file = os.path.join(restore_path, f"snapshot_{snapshot_id}.bin")
                with open(output_file, "wb") as out_fh:
                    for chunk_rec in chunk_records:
                        out_fh.write(cas.retrieve(chunk_rec.chunk_hash))
                        restored_hashes.append(chunk_rec.chunk_hash)

            # ------------------------------------------------------------------
            # Set VERIFYING state before Merkle integrity check
            # (Only verify full-snapshot restores; single-file restores skip root check)
            # ------------------------------------------------------------------
            job = db.get(RestoreJob, job_id)
            if job:
                job.status = JobStatus.verifying
                db.commit()

            if file_path is None:
                if not MerkleTree.verify(restored_hashes, snapshot.merkle_root):
                    from app.models.anomaly import AlertSeverity, AlertType, AnomalyAlert

                    alert = AnomalyAlert(
                        source_id=snapshot.source_id,
                        alert_type=AlertType.checksum_mismatch,
                        severity=AlertSeverity.critical,
                        detail=(
                            f"Merkle root mismatch during restore of snapshot {snapshot_id}. "
                            f"CAS store may be corrupt. Expected root: {snapshot.merkle_root}"
                        ),
                        metric_value=float(len(restored_hashes)),
                        threshold_value=float(snapshot.chunk_count),
                    )
                    db.add(alert)
                    db.commit()
                    raise ValueError(
                        f"Merkle root mismatch after restore: "
                        f"recomputed over {len(restored_hashes)} chunks does not match "
                        f"stored root {snapshot.merkle_root}"
                    )

            job = db.get(RestoreJob, job_id)
            if job:
                job.status = JobStatus.completed
                job.completed_at = datetime.now(timezone.utc)
                db.commit()

            logger.info(
                "Restore job %d completed: snapshot=%d, %d chunks → %s%s",
                job_id,
                snapshot_id,
                len(restored_hashes),
                restore_path,
                f" (file: {file_path})" if file_path else "",
            )

        except Exception as exc:
            logger.exception("Restore job %d failed: %s", job_id, exc)
            job = db.get(RestoreJob, job_id)
            if job:
                job.status = JobStatus.failed
                job.error_message = str(exc)
                db.commit()
            try:
                raise self.retry(exc=exc)
            except MaxRetriesExceededError:
                logger.error("Restore job %d exceeded max retries", job_id)
