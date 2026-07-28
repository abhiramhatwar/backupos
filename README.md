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
- Celery workers process backup and restore jobs with retry/backoff
- The entropy analyzer checks each new snapshot for ransomware-style encryption patterns

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                     FastAPI (async, uvicorn)                      │
│                                                                    │
│  Auth · Sources · Backups · Restore · Policies · Anomalies        │
│  WebSocket /ws/jobs/{id}  — live job progress stream              │
└──────────┬───────────────────────────┬───────────────────────────┘
           │                           │
  ┌────────▼────────┐         ┌────────▼────────┐
  │   PostgreSQL    │         │      Redis       │
  │                 │         │                  │
  │  Tenants        │         │  Celery broker   │
  │  Data sources   │         │  Result backend  │
  │  Backup jobs    │         │  Rate limit      │
  │  Snapshots      │         │  counters        │
  │  Policies       │         └─────────────────┘
  │  Audit log      │
  │  Alerts         │
  └────────┬────────┘
           │
  ┌────────▼──────────────────────────────────────────────────────┐
  │                  Celery Worker Pool (4 workers)                │
  │                                                                │
  │   ┌─────────────────────┐     ┌──────────────────────────┐   │
  │   │    run_backup task  │     │    run_restore task       │   │
  │   │                     │     │                           │   │
  │   │  1. Walk source dir │     │  1. Load snapshot chunks  │   │
  │   │  2. CDC chunk files │     │  2. Verify Merkle root    │   │
  │   │  3. CAS store       │     │  3. Reconstruct files     │   │
  │   │  4. Merkle tree     │     │  4. Write to restore path │   │
  │   │  5. Entropy check   │     └──────────────────────────┘   │
  │   │  6. Persist records │                                     │
  │   └─────────────────────┘                                     │
  └────────────────────────────┬──────────────────────────────────┘
                                │
                    ┌───────────▼───────────┐
                    │     CAS Block Store    │
                    │   (local filesystem)   │
                    │                        │
                    │  cas/ab/cdef12...      │
                    │  cas/f3/e9a701...      │
                    │  (SHA-256 addressed)   │
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

Properties:
- **Deduplication is automatic.** If a chunk already exists at its hash path, `store()` returns `(digest, is_new=False)` without writing.
- **Integrity is trivially verifiable.** Re-hash any stored block; if it does not match its filename, the block is corrupt.
- **Cross-source dedup.** Two completely different data sources sharing a common library or dataset share those blocks in the CAS with zero extra storage.

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

### Entropy-Based Ransomware Detection

**File:** `app/core/entropy.py`

Shannon entropy measures byte-level randomness:

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

BackupOS computes average chunk entropy per snapshot. An `entropy_spike` alert fires when **both** conditions hold:
1. Current average exceeds the policy threshold (default 7.2 bits/byte)
2. The delta from the previous snapshot exceeds 1.5 bits/byte

The delta condition prevents false positives on data that is legitimately high-entropy from the start (e.g. a source that only stores compressed images). The zero-baseline guard (`if previous_avg == 0.0: return False`) suppresses false alerts on first backups where no comparison is possible.

---

## System design

### Async API layer

The FastAPI application is fully async — every route, database call, and dependency uses `await`. SQLAlchemy async sessions are scoped per request via FastAPI dependency injection. Because FastAPI deduplicates same-signature dependencies within a request, `get_current_tenant` and the route handler share one session — no double-fetch, no phantom reads between them.

### Job orchestration

Backup and restore jobs are Celery tasks dispatched to a Redis broker. The API creates a `BackupJob` record with `status=pending` and dispatches asynchronously — the HTTP response returns immediately with the job ID. Workers pick up the task, update status through `pending → running → verifying → completed | failed`, and expose progress via the WebSocket endpoint.

Workers use synchronous SQLAlchemy (psycopg2) because Celery workers run outside an asyncio event loop. Failed tasks retry up to 3 times with a 60-second delay before writing `failed` status.

### Policy-as-code engine

Policies are defined in YAML, parsed into typed columns at write time, and evaluated by APScheduler every 5 minutes:

1. Query all sources with an attached active policy
2. Compare the last completed snapshot timestamp against `rpo_minutes`
3. Create `rpo_breach` alerts for sources that have exceeded their RPO
4. Check deduplication ratios and audit log completeness

Policy YAML is validated at the API layer — malformed YAML or missing required fields (`frequency_minutes`, `retention_days`, `rpo_minutes`) return HTTP 422 with field-level error messages before any database write.

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
| Migrations | Alembic |
| Job queue | Celery 5 + Redis 7 |
| Scheduling | APScheduler 3.10 |
| Storage | Local filesystem CAS (SHA-256 addressed blocks) |
| Auth | JWT (python-jose) + API key (`X-API-Key` header) |
| Rate limiting | Redis token bucket, 60 req/min per tenant |
| Containers | Docker + docker-compose |
| Testing | pytest-asyncio + httpx + aiosqlite (125 tests) |

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

Backup types: `full` (all chunks), `incremental` (Merkle diff against last snapshot)

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
| `POST` | `/restore` | Trigger a restore job |
| `GET` | `/restore/{job_id}` | Restore job status |
| `GET` | `/restore/{source_id}/verify/{snapshot_id}` | Verify Merkle integrity |

### Anomalies and compliance

| Method | Path | Description |
|---|---|---|
| `GET` | `/anomalies` | List unresolved alerts |
| `GET` | `/anomalies/{source_id}` | Alerts for a specific source |
| `POST` | `/anomalies/{alert_id}/resolve` | Resolve an alert |
| `GET` | `/anomalies/compliance/score` | Per-tenant compliance score (0–100) |
| `GET` | `/anomalies/compliance/report` | Full report with per-source violations |

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
tests/test_core.py          29 tests  — CDC, CAS, Merkle tree, Shannon entropy
tests/test_auth.py           9 tests  — register, JWT, API key auth, key rotation
tests/test_compliance.py    15 tests  — SOC 2, HIPAA, PCI scoring logic (pure unit)
tests/test_rate_limit.py     6 tests  — token bucket, Redis degradation paths
tests/test_policies.py      18 tests  — CRUD, PATCH, attach, tenant isolation
tests/test_anomalies.py     12 tests  — alert listing, compliance HTTP endpoints

125 tests total, 0 failures
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
9. Prints the full compliance report

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
[10] Generating compliance report …
    OK  Overall compliance score: 100.0 / 100
    OK  Total violations: 0
    OK  Source 'Demo Files': overall=100.0  SOC2=100.0  HIPAA=100.0  PCI=100.0
```
