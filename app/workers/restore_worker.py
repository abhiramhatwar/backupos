"""
Celery task: run_restore

Reconstructs a backed-up dataset from CAS chunks by reassembling them in
order from the BackupChunk records of the target snapshot.
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

# ---------------------------------------------------------------------------
# Synchronous engine (shared module-level to avoid re-creating per task)
# ---------------------------------------------------------------------------
_sync_url = settings.database_url.replace("+asyncpg", "")
_engine = create_engine(_sync_url, pool_pre_ping=True)
SyncSession: sessionmaker[Session] = sessionmaker(_engine, expire_on_commit=False)

cas = CASStore(settings.cas_store_path)


@celery_app.task(bind=True, max_retries=3, default_retry_delay=60)
def run_restore(self, job_id: int, snapshot_id: int, restore_path: str):
    """
    Restore a snapshot:

    1. Load BackupSnapshot and its ordered BackupChunk records
    2. Retrieve each chunk from CAS
    3. Reassemble and write to restore_path
    4. Verify restored data by recomputing the Merkle root
    5. Update RestoreJob status
    """
    from app.models.backup import BackupChunk, BackupSnapshot, JobStatus
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
            # ------------------------------------------------------------------
            # 1. Load snapshot and chunks
            # ------------------------------------------------------------------
            snapshot = db.get(BackupSnapshot, snapshot_id)
            if snapshot is None:
                raise ValueError(f"BackupSnapshot {snapshot_id} not found")

            chunks_stmt = (
                select(BackupChunk)
                .where(BackupChunk.snapshot_id == snapshot_id)
                .order_by(BackupChunk.id)
            )
            chunk_records = db.execute(chunks_stmt).scalars().all()

            # ------------------------------------------------------------------
            # 2 & 3. Retrieve chunks and write to restore_path
            # ------------------------------------------------------------------
            os.makedirs(restore_path, exist_ok=True)
            output_file = os.path.join(restore_path, f"snapshot_{snapshot_id}.bin")

            restored_hashes: list[str] = []
            with open(output_file, "wb") as out_fh:
                for chunk_rec in chunk_records:
                    data = cas.retrieve(chunk_rec.chunk_hash)
                    out_fh.write(data)
                    restored_hashes.append(chunk_rec.chunk_hash)

            # ------------------------------------------------------------------
            # 4. Verify Merkle root
            # ------------------------------------------------------------------
            if not MerkleTree.verify(restored_hashes, snapshot.merkle_root):
                raise ValueError(
                    f"Merkle root mismatch after restore: "
                    f"recomputed from {len(restored_hashes)} chunks does not match "
                    f"stored root {snapshot.merkle_root}"
                )

            # ------------------------------------------------------------------
            # 5. Mark COMPLETED
            # ------------------------------------------------------------------
            job = db.get(RestoreJob, job_id)
            if job:
                job.status = JobStatus.completed
                job.completed_at = datetime.now(timezone.utc)
                db.commit()

            logger.info(
                "Restore job %d completed: snapshot=%d, %d chunks → %s",
                job_id,
                snapshot_id,
                len(restored_hashes),
                output_file,
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
