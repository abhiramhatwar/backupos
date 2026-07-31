# BackupOS

A production-grade distributed backup engine that implements the core algorithms inside a cloud data protection system — content-defined chunking with Rabin fingerprinting, Merkle-tree snapshot verification, Shannon entropy ransomware detection, and a Celery-backed job orchestrator with real-time WebSocket streaming.

This is not a thin wrapper around cloud storage. It implements the hard parts from scratch. It ships with a full web dashboard and a one-command demo that simulates a ransomware attack and shows the detectors firing in real time.

---

## Quickstart

Four commands from a clean checkout to a fully-populated dashboard:

```bash
git clone https://github.com/abhiramhatwar/backupos
cd backupos
docker-compose up -d --build          # build & start api, worker, postgres, redis
docker-compose exec api python scripts/demo.py   # seed data + simulate a ransomware attack
```

Then open **http://localhost:8000** and sign in:

```
email:    demo@backupos.io
password: demo-password-123
```

> First build takes ~1–2 minutes. Wait for `docker-compose exec` to succeed (it retries the API automatically). If the dashboard shows nothing, give the API ~10s after `up` and refresh.

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
  - [Option A — Docker](#option-a--docker-recommended-zero-setup)
  - [Option B — Local Python](#option-b--local-python-no-docker)
  - [First API call](#first-api-call--register-and-authenticate)
  - [End-to-end walkthrough](#end-to-end-walkthrough)
- [The dashboard](#the-dashboard)
- [The demo & ransomware simulation](#the-demo--ransomware-simulation)
- [Common operations](#common-operations)
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
| Migrations | Alembic (4 migrations) |
| Job queue | Celery 5 + Redis 7 |
| Scheduling | APScheduler 3.10 (3 background jobs) |
| Storage | Local filesystem CAS (SHA-256 addressed, zstd compressed) |
| Auth | JWT (python-jose) + API key (`X-API-Key` header) |
| Rate limiting | Redis token bucket, 60 req/min per tenant |
| Metrics | Prometheus (`/metrics` via prometheus-fastapi-instrumentator) |
| Containers | Docker + docker-compose |
| Testing | pytest-asyncio + httpx + aiosqlite (208 tests) |

---

## Getting started

### Option A — Docker (recommended, zero setup)

**Prerequisites:** Docker Desktop (Mac/Windows) or Docker Engine + Docker Compose (Linux).

```bash
# 1. Clone
git clone https://github.com/abhiramhatwar/backupos
cd backupos

# 2. Start everything
docker-compose up --build
```

This command builds and starts four containers:

| Container | Role | Host port |
|---|---|---|
| `postgres` | PostgreSQL 16 | **5433** → 5432 |
| `redis` | Redis 7 | 6379 |
| `api` | FastAPI + Uvicorn | **8000** |
| `worker` | Celery worker pool (4 processes) | — |

> The Postgres container is published on host port **5433** (not 5432) so it never collides with a Postgres you may already run locally. Inside the Docker network the services still talk to it on `postgres:5432`.

The schema is created automatically the moment the API container starts. Wait for this log line before making requests:

```
api-1     | INFO:     Application startup complete.
```

**Verify it's healthy:**

```bash
curl http://localhost:8000/health
# {"status":"ok","service":"BackupOS"}
```

Now open one of:

| URL | What |
|---|---|
| **http://localhost:8000** | The web dashboard (sign in / register) |
| http://localhost:8000/docs | Interactive Swagger API explorer |
| http://localhost:8000/redoc | ReDoc API reference |
| http://localhost:8000/metrics | Prometheus metrics |

The fastest way to see everything working is to seed demo data — jump to [The demo & ransomware simulation](#the-demo--ransomware-simulation).

---

### Option B — Local Python (no Docker)

Use this if you want to run tests, iterate quickly, or do not have Docker.

**Prerequisites:** Python 3.10+, PostgreSQL 14+, Redis 6+.

```bash
# 1. Clone and enter the project
git clone https://github.com/abhiramhatwar/backupos
cd backupos

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set environment variables
#    Copy the sample file and edit as needed
cp .env.example .env               # if present, otherwise set manually:

export DATABASE_URL="postgresql+asyncpg://postgres:postgres@localhost:5432/backupos"
export REDIS_URL="redis://localhost:6379/0"
export SECRET_KEY="change-me-in-production"
export CAS_STORE_PATH="/tmp/backupos-cas"

# 5. Create the database (one time)
psql -U postgres -c "CREATE DATABASE backupos;"

# 6. Apply migrations
alembic upgrade head

# 7. Start the API server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# 8. (Optional) Start a Celery worker in a second terminal
celery -A app.workers.celery_app worker --loglevel=info --concurrency=4
```

The API is now at **http://localhost:8000**. Without the Celery worker, backup and restore jobs will be created but will fail at dispatch and immediately marked `failed` — all read-only and metadata endpoints still work.

---

### First API call — register and authenticate

All protected endpoints require a JWT. Create an account first:

```bash
# Register a tenant (name, email, and password are all required)
curl -s -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Acme Corp","email":"admin@example.com","password":"password123"}' | jq .

# Get a JWT
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"password123"}' | jq -r .access_token)

echo "Token: $TOKEN"

# Verify it works
curl -s http://localhost:8000/api/v1/auth/me \
  -H "Authorization: Bearer $TOKEN" | jq .
```

Use the token on every subsequent request via `-H "Authorization: Bearer $TOKEN"` or paste it into the Swagger UI **Authorize** button at http://localhost:8000/docs.

---

### End-to-end walkthrough

```bash
# 1. Create a data source
SOURCE=$(curl -s -X POST http://localhost:8000/api/v1/sources \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"My Files","source_type":"directory","path":"/tmp/mydata","classification":"internal"}' | jq .)
SOURCE_ID=$(echo $SOURCE | jq -r .id)
echo "Source ID: $SOURCE_ID"

# 2. Create a backup policy
POLICY=$(curl -s -X POST http://localhost:8000/api/v1/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Standard Policy",
    "policy_yaml": "frequency_minutes: 360\nretention_days: 90\nrpo_minutes: 720\nrequire_checksum: true\nentropy_threshold: 7.2"
  }' | jq .)
POLICY_ID=$(echo $POLICY | jq -r .id)

# 3. Attach the policy to the source
curl -s -X POST http://localhost:8000/api/v1/policies/$POLICY_ID/attach \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"source_id\": $SOURCE_ID}" | jq .

# 4. Trigger a full backup
JOB=$(curl -s -X POST http://localhost:8000/api/v1/backups \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"source_id\": $SOURCE_ID, \"backup_type\": \"full\"}" | jq .)
JOB_ID=$(echo $JOB | jq -r .id)
echo "Backup job ID: $JOB_ID"

# 5. Poll until done
curl -s http://localhost:8000/api/v1/backups/$JOB_ID \
  -H "Authorization: Bearer $TOKEN" | jq '{status: .status, error: .error_message}'

# 6. Check recovery metrics
curl -s http://localhost:8000/api/v1/backups/$SOURCE_ID/recovery-metrics \
  -H "Authorization: Bearer $TOKEN" | jq .

# 7. Browse the snapshot filesystem (no restore needed)
SNAP_ID=$(curl -s "http://localhost:8000/api/v1/backups/$SOURCE_ID/history" \
  -H "Authorization: Bearer $TOKEN" | jq -r '.[0].id')

curl -s "http://localhost:8000/api/v1/sources/$SOURCE_ID/snapshots/$SNAP_ID/browse?path=/" \
  -H "Authorization: Bearer $TOKEN" | jq .

# 8. Estimate restore cost before triggering restore
curl -s -X POST http://localhost:8000/api/v1/restore/estimate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"source_id\": $SOURCE_ID}" | jq .

# 9. View the backup chain dependency graph
curl -s http://localhost:8000/api/v1/sources/$SOURCE_ID/chain \
  -H "Authorization: Bearer $TOKEN" | jq .

# 10. Export the signed audit log
curl -s "http://localhost:8000/api/v1/compliance/audit-export" \
  -H "Authorization: Bearer $TOKEN" | jq '{event_count, signature, algorithm}'
```

---

---

## The dashboard

A single-page web UI is served from the API root at **http://localhost:8000**. It talks to the same `/api/v1` endpoints documented below, authenticates with a JWT stored in the browser, and streams live backup progress over the WebSocket.

Sign in on the landing screen (or register a new org). After seeding the demo, use `demo@backupos.io` / `demo-password-123`.

| Tab | What it shows |
|---|---|
| **Overview** | Stat cards (sources, jobs, snapshots, open alerts), a compliance-score gauge, and the most recent backup jobs |
| **Sources** | Register / delete data sources (directory, file, database) with a data classification |
| **Backups** | Trigger a backup and watch **live progress bars driven by the WebSocket** (`/ws/jobs/{id}`) |
| **Snapshots** | Per-source Merkle chain — dedup %, chunk counts, entropy, Merkle root, RPO/RTO recovery metrics, plus **verify** (recomputes the Merkle root) and **WORM lock** buttons |
| **Analytics** | Chart.js deduplicated-vs-raw storage growth chart + OLS capacity projection (30/90-day) |
| **Ransomware** | Shannon-entropy meter (0–8 bits/byte) and the list of active anomaly alerts, each resolvable inline |
| **Policies** | Policy-as-code YAML editor — create policies and attach them to sources |
| **Compliance** | SOC 2 / HIPAA / PCI-DSS score per source with the full violation trail |

The dashboard is plain HTML + vanilla JS (`web/index.html`, `web/app.js`) with Tailwind and Chart.js from CDNs — no build step. The API auto-reloads on edits to these files.

---

## The demo & ransomware simulation

`scripts/demo.py` seeds a realistic dataset so every dashboard tab is populated, and it stages a **simulated ransomware attack** to prove the detectors work.

Run it inside the `api` container so it shares the code bind-mount with the Celery worker (this is what makes the backed-up files visible to the worker):

```bash
docker-compose exec api python scripts/demo.py
```

What it does:

1. Registers the tenant `demo@backupos.io` and logs in
2. Creates a **Tier-1 Critical** policy (120-min RPO, 30-day retention, entropy threshold 7.5) and attaches it to both sources
3. **Source A — "Production Documents"**: a full backup followed by three incrementals that each add one file while leaving the rest unchanged, so you can watch the deduplication ratio climb (≈89% → 91%)
4. **Source B — "Customer DB Exports"**: a clean full + three identical daily incrementals (≈100% dedup), then it **overwrites every file with random bytes** to imitate ransomware encryption and runs one more backup
5. That final backup trips two independent detectors:
   - `entropy_spike` **(CRITICAL)** — average entropy jumps to ~7.9 bits/byte; the chi-squared test confirms the data is encrypted rather than merely compressed
   - `dedup_ratio_collapse` **(HIGH)** — chunk reuse collapses from ~100% to 0%
6. Prints recovery metrics and the compliance report (the attacked PII source scores lower)

Example tail of the output:

```
▶ Nightly incremental backup runs against the encrypted data…
    snapshot #9  dedup=0%  entropy=7.86 bits/byte  ← SPIKE

  ✓ 2 anomaly alert(s) raised:
    [HIGH    ] dedup_ratio_collapse: Dedup reuse collapsed from rolling avg 100.0% to 0.0% …
    [CRITICAL] entropy_spike: High entropy detected: avg=7.859 bits/byte … Chi-squared p=0.70 → ENCRYPTED …

  ✓ Overall compliance score: 85.2/100 (2 violations, 1 critical alerts)
```

The demo is idempotent on the tenant/policy but adds fresh snapshots each run. To start completely clean, reset the volumes first (see below).

---

## Common operations

| Goal | Command |
|---|---|
| Build & start (detached) | `docker-compose up -d --build` |
| Seed demo data | `docker-compose exec api python scripts/demo.py` |
| Follow logs | `docker-compose logs -f api worker` |
| Stop (keep data) | `docker-compose stop` |
| Start again | `docker-compose start` |
| Restart the worker after editing `app/workers/**` | `docker-compose restart worker` |
| **Full reset** (wipe DB + all backups) | `docker-compose down -v` then `up -d` again |
| Run the test suite | `docker-compose exec api python -m pytest -q` |

> The **API auto-reloads** on Python/HTML/JS edits (`--reload`). The **Celery worker does not** — after changing anything under `app/workers/`, run `docker-compose restart worker`.

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
| `POST` | `/backups/{source_id}/sample-change-rate` | Estimate how much data changed since last backup — returns `should_backup` flag |

Backup types: `full` (all chunks), `incremental` (Merkle diff against last snapshot)

**Change rate sampling** draws a random sample of chunk hashes from the latest snapshot and checks how many are absent from the previous snapshot. If fewer than 1% of sampled chunks changed, the backup is skippable. Configurable via `sample_size` and `change_threshold` query params.

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
| `POST` | `/restore/estimate` | Dry-run cost estimate — chunk count, bytes to read, estimated seconds, no CAS I/O |

**Restore estimate** aggregates chunk data from `SnapshotFile` manifests and uses `BackupChunk.compressed_size_bytes` for accurate byte estimates. Accepts an optional `file_path` to narrow the estimate to a single file. Returns deduplication savings (how many redundant chunk reads are avoided) alongside the time estimate.

### Virtual filesystem browser

| Method | Path | Description |
|---|---|---|
| `GET` | `/sources/{source_id}/snapshots/{snapshot_id}/browse` | Browse a snapshot as a filesystem — `?path=/var/www` |

No restore is performed. The tree is reconstructed in memory from `SnapshotFile` path records. Returns directories and files sorted dirs-first, with `child_count` for directories and `chunk_count` and `size` for files.

### Backup chain

| Method | Path | Description |
|---|---|---|
| `GET` | `/sources/{source_id}/chain` | Full DAG of snapshots with parent links, child lists, depth, lock status, and safe-to-delete flag |

A node is marked `safe_to_delete: true` when it has no child snapshots currently in the system and is not WORM-locked. Use this before pruning to identify which snapshots can be safely removed immediately.

### Webhooks

| Method | Path | Description |
|---|---|---|
| `POST` | `/webhooks` | Register a webhook endpoint (auto-generates HMAC secret) |
| `GET` | `/webhooks` | List all registered endpoints |
| `GET` | `/webhooks/{id}` | Get one endpoint (secret is never returned; 4-char hint only) |
| `DELETE` | `/webhooks/{id}` | Delete endpoint and all delivery history |
| `GET` | `/webhooks/{id}/deliveries` | Last 100 delivery attempts with HTTP status and signature |
| `POST` | `/webhooks/deliver` | Manually fire an event to a specific endpoint (for integration testing) |

Every delivery is signed with `HMAC-SHA256` and sent in the `X-BackupOS-Signature: sha256=<hex>` header. Delivery failures are recorded but do not block the caller.

### Anomalies and compliance

| Method | Path | Description |
|---|---|---|
| `GET` | `/anomalies` | List unresolved alerts |
| `GET` | `/anomalies/{source_id}` | Alerts for a specific source |
| `POST` | `/anomalies/{alert_id}/resolve` | Resolve an alert |
| `GET` | `/anomalies/compliance/score` | Per-tenant compliance score (0–100) |
| `GET` | `/anomalies/compliance/report` | Full report with per-source violations |
| `GET` | `/compliance/audit-export` | Export full audit log as a signed JSON compliance artifact |
| `GET` | `/compliance/audit-export/verify` | Re-derive the export signature to confirm a stored artifact is intact |

Alert types: `entropy_spike`, `backup_gap`, `rpo_violation`, `dedup_ratio_collapse`

**Signed audit export** uses a per-tenant HMAC-SHA256 derived key. Each event is serialised to canonical JSON (sorted keys), all rows are joined with `\n`, and a single digest is computed over the result. Downstream compliance systems can verify the export by reproducing the same digest. Supports `since`, `until`, `event_type`, and `limit` query params.

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
tests/test_core.py               29 tests  — CDC, CAS (dedup, compression, delete), Merkle tree, entropy (chi², EWMA)
tests/test_auth.py                9 tests  — register, JWT, API key auth, key rotation
tests/test_compliance.py         15 tests  — SOC 2, HIPAA, PCI scoring logic (pure unit)
tests/test_rate_limit.py          6 tests  — token bucket, Redis degradation paths
tests/test_policies.py           18 tests  — CRUD, PATCH, attach, tenant isolation
tests/test_anomalies.py          12 tests  — alert listing, compliance HTTP endpoints
tests/test_backups.py            13 tests  — trigger, list, history, recovery metrics
tests/test_sources.py             8 tests  — source CRUD, tenant isolation
tests/test_new_features.py       16 tests  — WORM lock, synthetic full, catalog search,
                                             file history, analytics, recovery verification
tests/test_browse.py             12 tests  — virtual filesystem browser, unit + integration
tests/test_restore_estimate.py   10 tests  — dry-run estimate, dedup savings, byte formula
tests/test_chain.py               8 tests  — DAG structure, safe-to-delete, lock propagation
tests/test_change_rate.py         8 tests  — no-change, full-change, partial, threshold logic
tests/test_webhooks.py           10 tests  — CRUD, HMAC signing, delivery history
tests/test_compliance_export.py  10 tests  — signed export, verify endpoint, signing helpers

208 tests total, 0 failures
```

Run the same suite inside Docker (no local Python needed):

```bash
docker-compose exec api python -m pytest -q
```

With coverage:

```bash
pytest tests/ --cov=app --cov-report=term-missing
```

The end-to-end demo and ransomware simulation are documented in [The demo & ransomware simulation](#the-demo--ransomware-simulation).
