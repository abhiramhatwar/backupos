# BackupOS

A production-grade distributed backup engine that implements the core algorithms inside a cloud data protection system — content-defined chunking with Rabin fingerprinting, Merkle-tree snapshot verification, Shannon entropy ransomware detection, and a Celery-backed job orchestrator with real-time WebSocket streaming.

This is not a thin wrapper around cloud storage. It implements the hard parts from scratch.

---

## Table of Contents

- [What it does](#what-it-does)
- [Architecture](#architecture)
- [Core algorithms](#core-algorithms)
  - [Content-Defined Chunking (CDC)](#content-defined-chunking-cdc)
  - [Content-Addressable Storage (CAS)](#content-addressable-storage-cas)
  - [Merkle Snapshot Trees](#merkle-snapshot-trees)
  - [Entropy-Based Ransomware Detection](#entropy-based-ransomware-detection)
- [System design](#system-design)
  - [Async API layer](#async-api-layer)
  - [Job orchestration](#job-orchestration)
  - [Policy-as-code engine](#policy-as-code-engine)
  - [WORM immutable snapshot lock](#worm-immutable-snapshot-lock)
  - [Automated recovery verification](#automated-recovery-verification)
  - [Synthetic full backup](#synthetic-full-backup)
  - [Backup catalog and file history](#backup-catalog-and-file-history)
  - [Storage analytics and growth projection](#storage-analytics-and-growth-projection)
  - [Compliance scoring](#compliance-scoring)
  - [Multi-tenant isolation](#multi-tenant-isolation)
  - [Rate limiting](#rate-limiting)
- [Tech stack](#tech-stack)
- [Getting started](#getting-started)
- [API reference](#api-reference)
- [Policy format](#policy-format)
- [Compliance framework mapping](#compliance-framework-mapping)
- [Running tests](#running-tests)
- [Demo script](#demo-script)

---

## What it does

BackupOS protects data sources (directories, files, databases) with incremental-forever backups. After the first full backup, subsequent jobs transfer only the blocks that changed — identical blocks across different files or versions are stored exactly once. Every snapshot is sealed with a Merkle root hash so integrity can be verified at any point in time without re-reading all the data.

The engine runs continuously in the background:
- APScheduler evaluates policies every five minutes and flags RPO violations
- APScheduler prunes expired snapshots every hour and GCs unreferenced CAS chunks
- APScheduler verifies snapshot Merkle integrity daily against all SnapshotFile manifests
- Celery workers process backup and restore jobs with retry/backoff
- The entropy analyzer checks each new snapshot for ransomware-style encryption patterns and dedup-ratio collapse

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        FastAPI (async, uvicorn)                           │
│                                                                            │
│  Auth · Sources · Backups · Snapshots · Restore · Policies · Anomalies   │
│  Analytics · Catalog · WebSocket /ws/jobs/{id}  — live job progress       │
└──────────┬───────────────────────────┬─────────────────────────────────-─┘
           │                           │
  ┌────────▼────────┐         ┌────────▼────────┐
  │   PostgreSQL    │         │      Redis       │
  │                 │         │                  │
  │  Tenants        │         │  Celery broker   │
  │  Data sources   │         │  Result backend  │
  │  Backup jobs    │         │  Rate limit      │
  │  Snapshots      │         │  counters        │
  │  SnapshotFiles  │         └─────────────────┘
  │  Policies       │
  │  Audit log      │
  │  Alerts         │
  └────────┬────────┘
           │
  ┌────────▼──────────────────────────────────────────────────────────────┐
  │                      Celery Worker Pool (4 workers)                    │
  │                                                                        │
  │   ┌─────────────────────┐          ┌──────────────────────────┐       │
  │   │    run_backup task  │          │    run_restore task       │       │
  │   │                     │          │                           │       │
  │   │  1. Walk source dir │          │  1. Load SnapshotFiles    │       │
  │   │  2. CDC chunk files │          │  2. Retrieve CAS chunks   │       │
  │   │  3. zstd compress   │          │  3. Status → VERIFYING    │       │
  │   │  4. CAS store       │          │  4. Merkle root check     │       │
  │   │  5. Merkle tree     │          │  5. Reconstruct files     │       │
  │   │  6. Entropy + chi²  │          └──────────────────────────┘       │
  │   │  7. EWMA baseline   │                                              │
  │   │  8. Persist records │                                              │
  │   └─────────────────────┘                                              │
  └────────────────────────────────┬───────────────────────────────────────┘
                                   │
                       ┌───────────▼───────────┐
                       │     CAS Block Store    │
                       │   (local filesystem)   │
                       │                        │
                       │  cas/ab/cdef12...      │
                       │  cas/f3/e9a701...      │
                       │  (SHA-256 addressed,   │
                       │   zstd compressed)     │
                       └────────────────────────┘
```

---

## Core algorithms

### Content-Defined Chunking (CDC)

**File:** `app/core/cdc.py`

Files are split into variable-length chunks using Rabin fingerprinting — the same algorithm used by Restic, Duplicacy, and AWS Backup internally.

A 48-byte sliding window rolls across the file bytes. At each position, a 64-bit rolling hash is maintained:

```
h[i] = h[i-1] * P + data[i] - data[i-W] * P^W   (mod 2^64)
```

Where:
- `P = 0x3DA3358B4DC173` — a prime polynomial chosen to minimize collisions
- `W = 48` — the window size
- `P^W` is precomputed into a 256-entry eviction table indexed by the outgoing byte, so each step is O(1)

A chunk boundary is cut when `h & 0x1FFF == 0`, producing an average chunk size of ~2 KB (1-in-8192 probability per byte). Boundaries are clamped to `[512 B, 8 KB]`.

**Why this matters for deduplication:** A position-based chunker (split every N bytes) re-chunks the entire file if a single byte is inserted at the start. CDC splits on content — insert a byte at the start and only the first few chunks change. Everything after the next natural boundary is identical to the previous backup and deduplicates for free.

```
File v1:  [AAAA|BBBB|CCCC|DDDD]       4 chunks stored
File v2:  [AAAA|BBBB|CCCC|DDDD+new]   3 chunks hit in CAS, 1 new chunk written
```

### Content-Addressable Storage (CAS)

**File:** `app/core/cas.py`

Every chunk is addressed by its SHA-256 hash and stored at `{cas_root}/{hash[:2]}/{hash}`. The two-character prefix directory avoids filesystem inode exhaustion on large block stores.

**Transparent zstd compression** — chunks with Shannon entropy below 7.2 bits/byte are compressed with zstd before writing. On `retrieve()`, the magic header `\x28\xb5\x2f\xfd` is detected and the chunk is decompressed transparently. High-entropy data (already compressed or encrypted) is stored raw to avoid wasted CPU.

Properties:
- **Deduplication is automatic.** If a chunk already exists at its hash path, `store()` returns `(digest, is_new=False, 0)` without writing.
- **Integrity is trivially verifiable.** Re-hash any stored block; if it does not match its filename, the block is corrupt.
- **Cross-source dedup.** Two completely different data sources sharing a common library or dataset share those blocks in the CAS with zero extra storage.
- **`store()` returns a 3-tuple** `(digest, is_new, stored_bytes)` — `stored_bytes` is the on-disk (post-compression) size, enabling chunk-level compression ratio tracking.

### Merkle Snapshot Trees

**File:** `app/core/merkle.py`

Each backup snapshot is a Merkle tree built over the SHA-256 hashes of all chunks in the snapshot:

```
          Root Hash
         /          \
    H(A,B)          H(C,D)
    /    \           /    \
 H(A)   H(B)     H(C)   H(D)
  A       B        C       D        ← chunk hashes (leaves)
```

Internal nodes: `sha256(left.hash + right.hash)`. Odd layers duplicate the last node to produce a complete binary tree.

**Incremental backup via tree diff:** `new_tree.diff(old_tree)` traverses the new tree and prunes any subtree whose root hash appears anywhere in the old tree. Only chunks belonging to new or modified subtrees are returned for transfer:

```
Complexity: O(changed data)  ←  Merkle tree traversal
            O(N)             ←  naive flat set difference (what this avoids)
```

**Point-in-time verification:** `MerkleTree.verify(chunk_hashes, expected_root)` rebuilds the tree from the stored chunk list and confirms the root matches the value recorded at backup time. If even a single chunk is corrupted or missing, the reconstructed root will differ.

**SnapshotFile as canonical truth:** Every backup writes a `SnapshotFile` record per file with the complete ordered list of chunk hashes. This means restore and verification can reconstruct the full Merkle root for any snapshot without relying on the incremental `BackupChunk` diff records — even for snapshots taken months apart in a long incremental chain.

### Entropy-Based Ransomware Detection

**File:** `app/core/entropy.py`

**Shannon entropy** measures byte-level randomness:

```
H(X) = -Σ p(x) * log2(p(x))     range: 0.0 – 8.0 bits/byte
```

Empirical thresholds:

| Data type | Typical entropy |
|---|---|
| English text | 4.0 – 5.5 |
| Executable binaries | 5.5 – 7.0 |
| Compressed data | 7.0 – 7.9 |
| Encrypted / ransomware-affected | 7.5 – 8.0 |

**Chi-squared uniformity test** — Shannon entropy alone cannot distinguish encrypted data from legitimately compressed data (both score ~8.0). The chi-squared test on byte frequency distribution provides the discriminating signal: truly random (encrypted) bytes produce near-uniform distributions (high p-value), while compressed data with its Huffman-coded structure produces non-uniform distributions (low p-value). The Wilson-Hilferty approximation avoids a scipy dependency.

**EWMA entropy baseline** — instead of comparing against a fixed prior snapshot, the detector maintains an Exponentially Weighted Moving Average (α = 0.3) over the last 10 snapshots. This makes the baseline adapt to sources that legitimately accumulate more compressed content over time, reducing false positive rates in mixed-workload environments.

**Dedup-ratio collapse detection** — a sudden drop in deduplication ratio (current ratio < 30% of rolling average across ≥3 prior snapshots) fires a separate `dedup_ratio_collapse` alert. Ransomware that re-encrypts previously deduplicated data will trigger this even if the entropy threshold is not crossed on the first backup.

---

## System design

### Async API layer

The FastAPI application is fully async — every route, database call, and dependency uses `await`. SQLAlchemy async sessions are scoped per request via FastAPI dependency injection. Because FastAPI deduplicates same-signature dependencies within a request, `get_current_tenant` and the route handler share one session — no double-fetch, no phantom reads between them.

### Job orchestration

Backup and restore jobs are Celery tasks dispatched to a Redis broker. The API creates a `BackupJob` record with `status=pending` and dispatches asynchronously — the HTTP response returns immediately with the job ID. Workers pick up the task, update status through `pending → running → verifying → completed | failed`, and expose progress via the WebSocket endpoint.

Workers use synchronous SQLAlchemy (psycopg2) because Celery workers run outside an asyncio event loop. Failed tasks retry up to 3 times with a 60-second delay before writing `failed` status.

The scheduler runs three background jobs inside the FastAPI process:

| Job | Interval | What it does |
|---|---|---|
| `policy_evaluator` | 5 min | Dispatch overdue backup jobs; raise RPO and backup-gap alerts |
| `retention_pruner` | 60 min | Delete expired snapshots (respects WORM locks); GC orphaned CAS chunks |
| `integrity_verifier` | 24 h | Recompute Merkle roots from SnapshotFile manifests; write `verification_status` |

### Policy-as-code engine

Policies are defined in YAML, parsed into typed columns at write time, and evaluated by APScheduler every 5 minutes:

1. Query all sources with an attached active policy
2. Compare the last completed snapshot timestamp against `rpo_minutes`
3. Create `rpo_breach` alerts for sources that have exceeded their RPO
4. Check deduplication ratios and audit log completeness

Policy YAML is validated at the API layer — malformed YAML or missing required fields (`frequency_minutes`, `retention_days`, `rpo_minutes`) return HTTP 422 with field-level error messages before any database write.

### WORM immutable snapshot lock

**File:** `app/api/snapshots.py`

Any snapshot can be placed under a Write-Once Read-Many (WORM) lock with a configurable expiry. While locked:
- The retention pruner silently skips it regardless of policy `retention_days`
- The delete endpoint refuses to remove it (404 or 403)
- The lock expiry is stored in `locked_until` and visible in all snapshot responses

Locks can be extended by re-calling the lock endpoint (updates `locked_until` to now + N days) or released early via the unlock endpoint. This models the regulatory hold patterns required by SOC 2, HIPAA, and PCI-DSS — a snapshot containing evidence for an active audit can be frozen in place without disabling the retention policy globally.

### Automated recovery verification

**File:** `app/core/scheduler.py` — `verify_snapshot_integrity()`

A daily APScheduler job finds snapshots that have never been verified or were last checked more than seven days ago (capped at 100 per run to bound execution time). For each:

1. Load all `SnapshotFile` records for the snapshot
2. Reconstruct the full ordered chunk hash list
3. Build a `MerkleTree` and compute the root hash
4. Compare against the stored `merkle_root` column
5. Write `verification_status = "passed" | "failed"` and `last_verified_at = now`

Any mismatch is logged as `WARNING` and surfaces in the snapshot API response. Operators can query `GET /api/v1/snapshots/{id}` to check `verification_status` without waiting for the next scheduled run.

This is the approach used by enterprise backup systems to detect silent data corruption (bit rot, storage hardware failure) before a restore is actually needed.

### Synthetic full backup

**File:** `app/api/backups.py` — `POST /{source_id}/synthesize-full`

In a long incremental-forever chain, restoring the most recent snapshot requires replaying every incremental since the last full. The synthetic full operation collapses that dependency:

1. Load all `SnapshotFile` records from the latest snapshot (already carries the complete file manifest — no chain traversal needed)
2. Recompute the Merkle root from those records
3. Create a new `BackupJob` (status `completed`) and a new `BackupSnapshot` with `parent_snapshot_id = NULL`
4. Clone all `SnapshotFile` records into the synthetic snapshot

**No CAS I/O.** The underlying chunk data is already stored — the synthesis is a pure metadata operation. The result is a self-contained full snapshot that can serve as the new base for future incrementals, letting the operator safely prune the old chain without losing any data.

### Backup catalog and file history

**File:** `app/api/catalog.py`

**Catalog search** — `GET /api/v1/sources/{source_id}/catalog?q=<glob>` accepts any `fnmatch` glob pattern and matches it against the `file_path` of every `SnapshotFile` record in the target snapshot (defaults to latest). Returns matching paths with file sizes and chunk counts. Useful for locating a specific database dump, log archive, or config file within a large backup without restoring the full snapshot.

**File version history** — `GET /api/v1/sources/{source_id}/files/{path}/history` returns every version of a specific file path across all snapshots, newest first. Each entry carries a `changed` flag computed by diffing chunk hashes against the previous (older) version — `changed: true` means the file's content differed from the snapshot before it. This lets operators instantly identify which backup contains the last known-good version of a file before a corruption or accidental deletion.

### Storage analytics and growth projection

**File:** `app/api/analytics.py`

`GET /api/v1/analytics/sources/{source_id}` returns:

- **Per-snapshot trends** — `total_size_bytes`, `dedup_size_bytes`, `dedup_ratio`, `chunk_count`, `average_entropy` for every snapshot in chronological order
- **Compression savings** — aggregate bytes saved by zstd compression across all chunk records
- **Growth projection** — ordinary least squares linear regression on deduplicated storage size over time, exposing `slope_bytes_per_day`, 30-day and 90-day projections, and `r_squared` as a confidence indicator

The growth projection models actual on-disk usage after deduplication — the metric that determines when storage infrastructure needs to be expanded. An `r_squared` above 0.85 indicates a linear growth trend where the 30-day and 90-day projections are reliable for capacity planning.

### Compliance scoring

Each source is scored independently against three frameworks, starting at 100 points. Violations deduct fixed amounts. The overall tenant score is the mean of all applicable framework scores.

The compliance report is generated on demand from live database state — no materialized cache that can go stale. The violations list includes a human-readable explanation for every deduction.

### Multi-tenant isolation

Every data model carries a `tenant_id` foreign key. Every query predicate includes `WHERE tenant_id = :current_tenant`. No route can reach across tenant boundaries by accident — the auth layer resolves the tenant before any business logic runs, and all lookups filter by it explicitly.

### Rate limiting

Redis token bucket per tenant. Key: `rate_limit:{tenant_id}`, TTL: 60 seconds. On the first request in a window, the key is created and the TTL is set atomically. Requests beyond 60/min return HTTP 429. Redis connection failures are swallowed — the limiter degrades gracefully rather than taking the API down with it.

---

## Tech stack

| Layer | Technology |
|---|---|
| API | FastAPI 0.115 + Pydantic v2 (fully async) |
| Database | PostgreSQL 16 + SQLAlchemy 2.0 async |
| Migrations | Alembic (003 migrations) |
| Job queue | Celery 5 + Redis 7 |
| Scheduling | APScheduler 3.10 (3 background jobs) |
| Storage | Local filesystem CAS (SHA-256 addressed, zstd compressed) |
| Auth | JWT (python-jose) + API key (`X-API-Key` header) |
| Rate limiting | Redis token bucket, 60 req/min per tenant |
| Metrics | Prometheus (`/metrics` via prometheus-fastapi-instrumentator) |
| Containers | Docker + docker-compose |
| Testing | pytest-asyncio + httpx + aiosqlite (150 tests) |

---

## Getting started

**Prerequisites:** Docker and Docker Compose.

```bash
git clone https://github.com/abhiramhatwar/backupos
cd backupos
docker-compose up --build
```

This starts four containers: PostgreSQL 16, Redis 7, the FastAPI API server, and a Celery worker pool (4 concurrent workers). Alembic migrations run automatically on API startup.

- Interactive docs: [http://localhost:8000/docs](http://localhost:8000/docs)
- Redoc: [http://localhost:8000/redoc](http://localhost:8000/redoc)
- Prometheus metrics: [http://localhost:8000/metrics](http://localhost:8000/metrics)

---

## API reference

All endpoints are under `/api/v1`. Authentication is required unless noted.

### Auth

| Method | Path | Description |
|---|---|---|
| `POST` | `/auth/register` | Create a new tenant account |
| `POST` | `/auth/token` | Exchange credentials for a JWT |
| `POST` | `/auth/api-key/rotate` | Rotate the tenant's API key |
| `GET` | `/auth/me` | Current tenant profile |

Two auth methods are accepted on all protected endpoints:
- `Authorization: Bearer <jwt>` — short-lived JWT from `/auth/token`
- `X-API-Key: <key>` — long-lived API key, rotatable on demand

### Data sources

| Method | Path | Description |
|---|---|---|
| `POST` | `/sources` | Register a data source |
| `GET` | `/sources` | List sources (`?page=1&page_size=20`) |
| `GET` | `/sources/{id}` | Get a source |
| `PATCH` | `/sources/{id}` | Update source metadata |
| `DELETE` | `/sources/{id}` | Delete a source |

Source classifications: `internal`, `pii`, `financial`, `public`

### Backups

| Method | Path | Description |
|---|---|---|
| `POST` | `/backups` | Trigger a backup job |
| `GET` | `/backups` | List jobs (paginated) |
| `GET` | `/backups/{job_id}` | Job status and metadata |
| `GET` | `/backups/{source_id}/history` | Snapshot history |
| `GET` | `/backups/{source_id}/recovery-metrics` | RPO/RTO metrics |
| `POST` | `/backups/{source_id}/synthesize-full` | Synthesize a chain-free full snapshot (metadata-only) |

Backup types: `full` (all chunks), `incremental` (Merkle diff against last snapshot)

### Snapshots

| Method | Path | Description |
|---|---|---|
| `GET` | `/snapshots/{id}` | Snapshot metadata including lock and verification state |
| `POST` | `/snapshots/{id}/lock` | Apply a WORM immutable lock (`{"lock_days": 30}`) |
| `DELETE` | `/snapshots/{id}/lock` | Remove the lock before expiry |

### Catalog

| Method | Path | Description |
|---|---|---|
| `GET` | `/sources/{source_id}/catalog?q=<glob>` | Search files by glob pattern in a snapshot |
| `GET` | `/sources/{source_id}/files/{path}/history` | All backup versions of a file with change flags |

The `catalog` endpoint accepts a `snapshot_id` query parameter to search a specific snapshot instead of the latest.

### Analytics

| Method | Path | Description |
|---|---|---|
| `GET` | `/analytics/sources/{source_id}` | Dedup/compression trends and linear growth projection |

### Policies

| Method | Path | Description |
|---|---|---|
| `POST` | `/policies` | Create a policy from YAML |
| `GET` | `/policies` | List policies |
| `GET` | `/policies/{id}` | Get a policy |
| `PATCH` | `/policies/{id}` | Partial update (name, yaml, is_active) |
| `POST` | `/policies/{id}/attach` | Attach policy to a source |
| `DELETE` | `/policies/{id}` | Delete a policy |

### Restore

| Method | Path | Description |
|---|---|---|
| `POST` | `/restore` | Trigger a restore job (full snapshot or single file via `file_path`) |
| `GET` | `/restore/{job_id}` | Restore job status |
| `GET` | `/restore/{source_id}/verify/{snapshot_id}` | Verify Merkle integrity on demand |

### Anomalies and compliance

| Method | Path | Description |
|---|---|---|
| `GET` | `/anomalies` | List unresolved alerts |
| `GET` | `/anomalies/{source_id}` | Alerts for a specific source |
| `POST` | `/anomalies/{alert_id}/resolve` | Resolve an alert |
| `GET` | `/anomalies/compliance/score` | Per-tenant compliance score (0–100) |
| `GET` | `/anomalies/compliance/report` | Full report with per-source violations |

Alert types: `entropy_spike`, `backup_gap`, `rpo_violation`, `dedup_ratio_collapse`

### WebSocket

```
WS /ws/jobs/{job_id}
```

Streams job state change events as JSON. Useful for real-time dashboards.

---

## Policy format

```yaml
# Required
frequency_minutes: 360     # target backup interval
retention_days: 90         # snapshot retention window
rpo_minutes: 720           # alert if no backup within this many minutes

# Optional (default false / null)
require_checksum: true     # fail restore if chunk digest mismatches stored hash
require_dedup: true        # reject jobs that skip deduplication
entropy_threshold: 7.2     # ransomware alert threshold in bits/byte (0.0–8.0)
```

Missing required fields or malformed YAML returns HTTP 422 with field-level error detail.

---

## Compliance framework mapping

| Control | SOC 2 | HIPAA (PII sources) | PCI-DSS (financial sources) |
|---|---|---|---|
| Backup policy attached | −50 if absent | −100 if absent | −100 if absent |
| Checksum verification | −25 if absent | −33 if absent | — |
| Deduplication | — | −33 if absent | — |
| Retention ≥ 30 days | −25 if below | — | — |
| Retention ≥ 365 days | — | −34 if below | −50 if below |
| Backup frequency ≤ daily | — | — | −50 if below |
| RPO ≤ 1440 min (24h) | −25 if exceeded | — | — |
| No unresolved critical alerts | −25 per batch | — | — |

Overall score = mean of applicable framework scores. A source with no PII or financial classification is scored only on SOC 2.

---

## Running tests

Tests use an in-memory SQLite database and an ASGI test client — no running Postgres or Redis required.

```bash
pip install -r requirements.txt
pytest tests/ -v
```

```
tests/test_core.py            29 tests  — CDC, CAS (dedup, compression, delete), Merkle tree, entropy (chi², EWMA)
tests/test_auth.py             9 tests  — register, JWT, API key auth, key rotation
tests/test_compliance.py      15 tests  — SOC 2, HIPAA, PCI scoring logic (pure unit)
tests/test_rate_limit.py       6 tests  — token bucket, Redis degradation paths
tests/test_policies.py        18 tests  — CRUD, PATCH, attach, tenant isolation
tests/test_anomalies.py       12 tests  — alert listing, compliance HTTP endpoints
tests/test_backups.py         13 tests  — trigger, list, history, recovery metrics
tests/test_sources.py          8 tests  — source CRUD, tenant isolation
tests/test_new_features.py    16 tests  — WORM lock, synthetic full, catalog search,
                                          file history, analytics, recovery verification

150 tests total, 0 failures
```

With coverage:

```bash
pytest tests/ --cov=app --cov-report=term-missing
```

---

## Demo script

With the stack running (`docker-compose up -d`):

```bash
python scripts/demo.py
```

The script:
1. Registers a tenant and obtains a JWT
2. Creates a data source pointing at `/tmp/demo_data`
3. Creates a backup policy (60-minute frequency, 30-day retention, 120-minute RPO)
4. Attaches the policy to the source
5. Writes 5 sample files (~5 KB each) to the source directory
6. Triggers a **full backup** and polls until complete
7. Appends data to one file, then triggers an **incremental backup** — only changed chunks are transferred
8. Fetches recovery metrics (current RPO, estimated RTO, total snapshot count)
9. Synthesizes a full snapshot from the incremental chain
10. Searches the backup catalog for `*.txt` files
11. Prints the storage analytics report (dedup ratio, compression savings, growth projection)
12. Prints the full compliance report

Example output:

```
============================================================
  BackupOS End-to-End Demo
============================================================

[6] Triggering full backup …
    OK  Backup job created: id=1, status=pending
[7] Polling backup job status …
    OK  Job finished with status: completed
[9] Triggering incremental backup …
    OK  Incremental job finished with status: completed
[11] Synthesizing full snapshot …
    OK  Synthetic snapshot id=3, 5 files, 12 chunks, no chain dependency
[12] Generating compliance report …
    OK  Overall compliance score: 100.0 / 100
    OK  Total violations: 0
    OK  Source 'Demo Files': overall=100.0  SOC2=100.0  HIPAA=100.0  PCI=100.0
```
