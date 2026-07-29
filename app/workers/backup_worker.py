"""
Celery task: run_backup

Uses synchronous SQLAlchemy (psycopg2) because Celery workers do not have
an asyncio event loop running.

Key behaviours
--------------
* Incremental backups only write *new* chunks to the backup_chunks table;
  chunks already stored in a previous snapshot are not re-recorded (dedup).
  The full chunk manifest is preserved in SnapshotFile records so that
  verify_snapshot and restore_worker can reconstruct the complete picture.

* Entropy anomaly detection uses an EWMA baseline over the last 10 snapshots
  rather than a single-snapshot comparison, so one legitimately high-entropy
  backup doesn't permanently elevate the baseline.

* A chi-squared uniformity test distinguishes *encrypted* data (uniform byte
  histogram, high p-value) from *compressed* data (non-uniform, low p-value).
  Both have high Shannon entropy but only encrypted data is suspicious.

* Dedup-ratio collapse detection flags backups where the deduplication ratio
  drops sharply relative to the recent rolling average — a strong signal that
  data has been re-encrypted or scrambled by ransomware.
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
from app.core.entropy import (
    chi_squared_uniform_test,
    entropy_spike_detected,
    ewma_entropy_baseline,
    shannon_entropy as _entropy,
)
from app.core.merkle import MerkleTree
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

_sync_url = settings.database_url.replace("+asyncpg", "")
_engine = create_engine(_sync_url, pool_pre_ping=True)
SyncSession: sessionmaker[Session] = sessionmaker(_engine, expire_on_commit=False)

cas = CASStore(settings.cas_store_path)
chunker = CDCChunker()


def _update_job(db: Session, job_id: int, **kwargs) -> None:
    from app.models.backup import BackupJob

    job = db.get(BackupJob, job_id)
    if job is None:
        return
    for k, v in kwargs.items():
        setattr(job, k, v)
    db.commit()


@celery_app.task(bind=True, max_retries=3, default_retry_delay=60)
def run_backup(self, job_id: int, source_path: str, source_id: int, backup_type: str):
    """
    Execute a backup job end-to-end:

    1. Mark job RUNNING
    2. Chunk all files under source_path with CDC
    3. Store each chunk in CAS (deduplication + compression are automatic)
    4. Build MerkleTree; diff against previous snapshot for incremental
    5. Persist BackupSnapshot + SnapshotFile records
    6. Write BackupChunk records (new chunks only for incremental backups)
    7. Run anomaly detection (entropy / dedup-ratio / size)
    8. Mark job COMPLETED
    """
    from app.models.anomaly import AlertSeverity, AlertType, AnomalyAlert
    from app.models.backup import (
        BackupChunk,
        BackupJob,
        BackupSnapshot,
        BackupType,
        JobStatus,
        SnapshotFile,
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
            file_manifest: list[tuple[str, int, list[bytes]]] = []

            if os.path.isfile(source_path):
                with open(source_path, "rb") as f:
                    data = f.read()
                file_chunks = chunker.chunk_data(data)
                all_chunks.extend(file_chunks)
                file_manifest.append((os.path.basename(source_path), len(data), file_chunks))
            elif os.path.isdir(source_path):
                for root, _dirs, files in os.walk(source_path):
                    for fname in sorted(files):
                        fpath = os.path.join(root, fname)
                        rel_path = os.path.relpath(fpath, source_path)
                        try:
                            with open(fpath, "rb") as f:
                                data = f.read()
                            file_chunks = chunker.chunk_data(data)
                            all_chunks.extend(file_chunks)
                            file_manifest.append((rel_path, len(data), file_chunks))
                        except OSError as exc:
                            logger.warning("Skipping %s: %s", fpath, exc)
            else:
                logger.warning("source_path %s does not exist; creating empty snapshot", source_path)

            # ------------------------------------------------------------------
            # 3. Store chunks in CAS — compute per-chunk entropy in the same pass
            #    CASStore.store() transparently compresses low-entropy chunks.
            # ------------------------------------------------------------------
            chunk_hashes: list[str] = []
            chunk_sizes: list[int] = []
            chunk_stored_sizes: list[int] = []
            chunk_is_new: list[bool] = []
            chunk_entropies: list[float] = []

            for chunk in all_chunks:
                entropy_val = _entropy(chunk)
                digest, is_new, stored_size = cas.store(chunk, entropy=entropy_val)
                chunk_hashes.append(digest)
                chunk_sizes.append(len(chunk))
                chunk_stored_sizes.append(stored_size)
                chunk_is_new.append(is_new)
                chunk_entropies.append(entropy_val)

            # ------------------------------------------------------------------
            # 4. Build Merkle tree; compute diff against previous snapshot
            # ------------------------------------------------------------------
            tree = MerkleTree(chunk_hashes)

            prev_snapshot = None
            if backup_type == BackupType.incremental or backup_type == "incremental":
                prev_stmt = (
                    select(BackupSnapshot)
                    .where(BackupSnapshot.source_id == source_id)
                    .order_by(BackupSnapshot.created_at.desc())
                    .limit(1)
                )
                prev_snapshot = db.execute(prev_stmt).scalar_one_or_none()

            if prev_snapshot is not None:
                prev_hashes_stmt = select(BackupChunk.chunk_hash).where(
                    BackupChunk.snapshot_id == prev_snapshot.id
                )
                prev_hash_rows = db.execute(prev_hashes_stmt).scalars().all()
                prev_tree = MerkleTree(list(prev_hash_rows))
                new_hashes: set[str] = set(tree.diff(prev_tree))
            else:
                new_hashes = set(chunk_hashes)

            # ------------------------------------------------------------------
            # 5. Compute summary metrics
            # ------------------------------------------------------------------
            avg_entropy = (sum(chunk_entropies) / len(chunk_entropies)) if chunk_entropies else 0.0
            total_size = sum(chunk_sizes)
            dedup_size = sum(s for s, is_new in zip(chunk_sizes, chunk_is_new) if not is_new)
            new_count = len(new_hashes)

            # ------------------------------------------------------------------
            # 6. Persist BackupSnapshot, SnapshotFile manifests, and BackupChunks
            #    For incremental backups, only new chunks are written to backup_chunks.
            #    SnapshotFile records always contain the complete per-file hash list
            #    so verify_snapshot and restore_worker always have the full picture.
            # ------------------------------------------------------------------
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
            db.flush()

            # SnapshotFile: complete manifest (all chunks, new and inherited)
            chunk_offset = 0
            for rel_path, file_size, file_chunks in file_manifest:
                file_hashes = []
                for _ in file_chunks:
                    file_hashes.append(chunk_hashes[chunk_offset])
                    chunk_offset += 1
                sf = SnapshotFile(
                    snapshot_id=snapshot.id,
                    file_path=rel_path,
                    file_size=file_size,
                    chunk_hashes=SnapshotFile.encode_chunk_hashes(file_hashes),
                )
                db.add(sf)

            # BackupChunk: only new chunks (avoids re-recording inherited chunks)
            for digest, size, stored_size, entropy_val in zip(
                chunk_hashes,
                chunk_sizes,
                chunk_stored_sizes,
                chunk_entropies,
            ):
                if digest not in new_hashes:
                    continue
                chunk_rec = BackupChunk(
                    snapshot_id=snapshot.id,
                    chunk_hash=digest,
                    size_bytes=size,
                    compressed_size_bytes=stored_size,
                    entropy=entropy_val,
                    is_new=True,
                )
                db.add(chunk_rec)

            db.commit()

            # ------------------------------------------------------------------
            # 7. Anomaly detection
            # ------------------------------------------------------------------
            # Gather recent snapshots for rolling baselines
            recent_stmt = (
                select(BackupSnapshot)
                .where(BackupSnapshot.source_id == source_id)
                .order_by(BackupSnapshot.created_at.desc())
                .limit(10)
            )
            recent = db.execute(recent_stmt).scalars().all()
            prev_snapshots = [s for s in recent if s.id != snapshot.id]

            # --- Policy threshold ---
            policy_threshold = 7.5
            try:
                policy_stmt = (
                    select(BackupPolicy)
                    .join(PolicyAttachment, PolicyAttachment.policy_id == BackupPolicy.id)
                    .where(PolicyAttachment.source_id == source_id)
                    .limit(1)
                )
                policy = db.execute(policy_stmt).scalar_one_or_none()
                if policy:
                    policy_threshold = policy.entropy_threshold
            except Exception:
                pass

            # --- EWMA entropy baseline (oldest-first for correct EWMA order) ---
            historical_entropies = [
                s.average_entropy for s in reversed(prev_snapshots) if s.average_entropy
            ]
            ewma_baseline = ewma_entropy_baseline(historical_entropies)

            entropy_alert_fired = False
            if avg_entropy > policy_threshold or entropy_spike_detected(avg_entropy, ewma_baseline):
                # Chi-squared test: distinguish encrypted from merely-compressed data
                sample = b"".join(all_chunks[:20]) if all_chunks else b""
                p_value = chi_squared_uniform_test(sample)
                is_encrypted = p_value > 0.05

                detail = (
                    f"High entropy detected: avg={avg_entropy:.3f} bits/byte "
                    f"(threshold={policy_threshold}, EWMA baseline={ewma_baseline:.3f}). "
                    f"Chi-squared p={p_value:.4f} → {'ENCRYPTED' if is_encrypted else 'compressed'}. "
                    f"{'Possible ransomware activity.' if is_encrypted else 'Likely compressed data.'}"
                )
                alert = AnomalyAlert(
                    source_id=source_id,
                    alert_type=AlertType.entropy_spike,
                    severity=AlertSeverity.critical if is_encrypted else AlertSeverity.medium,
                    detail=detail,
                    metric_value=avg_entropy,
                    threshold_value=policy_threshold,
                )
                db.add(alert)
                entropy_alert_fired = True

            # --- Dedup-ratio collapse detection ---
            if prev_snapshots and total_size > 0:
                recent_ratios = [
                    s.dedup_size_bytes / s.total_size_bytes
                    for s in prev_snapshots
                    if s.total_size_bytes > 0
                ]
                if len(recent_ratios) >= 3:
                    avg_dedup_ratio = sum(recent_ratios) / len(recent_ratios)
                    current_dedup_ratio = dedup_size / total_size
                    if avg_dedup_ratio > 0.3 and current_dedup_ratio < avg_dedup_ratio * 0.3:
                        dedup_alert = AnomalyAlert(
                            source_id=source_id,
                            alert_type=AlertType.dedup_ratio_collapse,
                            severity=AlertSeverity.high,
                            detail=(
                                f"Dedup ratio collapsed from rolling avg {avg_dedup_ratio:.1%} "
                                f"to {current_dedup_ratio:.1%}. Data may have been re-encrypted "
                                f"or replaced wholesale — possible ransomware activity."
                            ),
                            metric_value=current_dedup_ratio,
                            threshold_value=avg_dedup_ratio * 0.3,
                        )
                        db.add(dedup_alert)

            # --- Size anomaly (3× rolling average) ---
            if len(prev_snapshots) >= 2:
                sizes = [s.total_size_bytes for s in prev_snapshots]
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
                "Backup job %d completed: %d chunks (%d new), merkle=%s, avg_entropy=%.3f",
                job_id,
                len(chunk_hashes),
                new_count,
                tree.root_hash[:12],
                avg_entropy,
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
