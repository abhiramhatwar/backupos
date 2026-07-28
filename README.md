# BackupOS

A production-grade distributed backup engine built with FastAPI. Implements the core algorithms behind cloud data protection systems: content-defined chunking, content-addressable deduplication, Merkle-tree snapshot verification, and entropy-based ransomware detection.

## What it does

BackupOS protects data sources (directories, files, databases) with incremental-forever backups — only changed blocks are transferred after the first full backup. Every snapshot is verifiable via a Merkle root hash, and the system continuously monitors backup entropy to detect ransomware-style encryption patterns before they propagate.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   FastAPI (async)                    │
│   Auth · Sources · Backups · Policies · Recovery     │
│             WebSocket (live job stream)              │
└────────────┬──────────────────────┬─────────────────┘
             │                      │
    ┌────────▼────────┐    ┌────────▼────────┐
    │   PostgreSQL    │    │      Redis       │
    │  job metadata   │    │  job queue (MQ)  │
    │  audit log      │    │  rate limiting   │
    │  policy state   │    └─────────────────┘
    └────────┬────────┘
             │
    ┌────────▼────────────────────────────────────────┐
    │              Celery Worker Pool                  │
    │                                                  │
    │  ┌──────────────┐    ┌─────────────────────┐    │
    │  │ CDC Chunker  │    │   Shannon Entropy    │    │
    │  │ (Rabin f.p.) │    │  Ransomware Detector │    │
    │  └──────┬───────┘    └─────────────────────┘    │
    │         │                                        │
    │  ┌──────▼───────┐    ┌─────────────────────┐    │
    │  │  CAS Store   │    │    Merkle Tree       │    │
    │  │ (SHA-256 CAS)│    │  Snapshot Verifier   │    │
    │  └──────────────┘    └─────────────────────┘    │
    └─────────────────────────────────────────────────┘
             │
    ┌────────▼────────┐
    │   Local Disk    │
    │  (CAS blocks)   │
    └─────────────────┘
```

## Core algorithms

### Content-Defined Chunking (CDC)
Uses Rabin fingerprinting with a 48-byte sliding window to split files into variable-length chunks (512B–8KB, ~2KB average). Chunk boundaries are content-driven, not position-driven — inserting a byte at the start of a file only invalidates the first few chunks, not the entire file.

### Content-Addressable Storage (CAS)
Every chunk is addressed by its SHA-256 hash and stored once globally. Two files with a shared 100MB block store that block exactly once. Deduplication is automatic and cross-source.

### Merkle Snapshot Trees
Each backup snapshot is a Merkle tree over its chunk hashes. An incremental backup computes `tree.diff(prev_tree)` — only the chunks absent from the previous snapshot are transferred. Restoring any snapshot to a verified state requires only the Merkle root hash.

### Shannon Entropy Ransomware Detection
Shannon entropy measures byte-level randomness (0–8 bits/byte). Encrypted files sit near 7.9; plaintext sits near 4–5. BackupOS tracks average entropy per snapshot and fires an `entropy_spike` alert when:
- Average entropy exceeds the policy threshold (default 7.5 bits/byte), OR
- Entropy jumps >1.5 bits/byte compared to the previous snapshot

## Tech stack

| Layer | Technology |
|---|---|
| API | FastAPI + Pydantic v2 (fully async) |
| Database | PostgreSQL + SQLAlchemy (async) |
| Job queue | Celery + Redis |
| Scheduling | APScheduler (policy evaluation every 5 min) |
| Storage | Local filesystem CAS (SHA-256 addressed blocks) |
| Auth | JWT Bearer + API key (`X-API-Key` header) |
| Rate limiting | Redis token bucket (60 req/min per tenant) |
| Containers | Docker + docker-compose |

## Getting started

**Prerequisites:** Docker + Docker Compose

```bash
git clone https://github.com/abhiramhatwar/backupos
cd backupos
cp .env.example .env
docker-compose up --build
```

API is available at `http://localhost:8000`.  
Interactive docs: `http://localhost:8000/docs`

## API overview

### Auth
```
POST /api/v1/auth/register      Register a new tenant
POST /api/v1/auth/token         Get JWT access token
POST /api/v1/auth/api-key/rotate Rotate API key
GET  /api/v1/auth/me            Current tenant info
```

### Data sources
```
POST   /api/v1/sources          Register a data source
GET    /api/v1/sources          List sources (paginated)
GET    /api/v1/sources/{id}     Get source
PATCH  /api/v1/sources/{id}     Update source
DELETE /api/v1/sources/{id}     Delete source
```

### Backups
```
POST /api/v1/backups                        Trigger backup job
GET  /api/v1/backups                        List jobs (paginated)
GET  /api/v1/backups/{job_id}               Job status
GET  /api/v1/backups/{source_id}/history    Snapshot history
GET  /api/v1/backups/{source_id}/recovery-metrics  RPO/RTO metrics
```

### Policies (YAML-as-code)
```
POST /api/v1/policies               Create policy
GET  /api/v1/policies               List policies
GET  /api/v1/policies/{id}          Get policy
POST /api/v1/policies/{id}/attach   Attach to source
DELETE /api/v1/policies/{id}        Delete policy
```

### Recovery
```
POST /api/v1/restore                          Trigger restore
GET  /api/v1/restore/{job_id}                 Restore status
GET  /api/v1/restore/{source_id}/verify/{snapshot_id}  Verify snapshot integrity
```

### Anomalies & compliance
```
GET  /api/v1/anomalies                List unresolved alerts
GET  /api/v1/anomalies/{source_id}    Alerts for a source
POST /api/v1/anomalies/{id}/resolve   Resolve alert
GET  /api/v1/anomalies/compliance/report  Full compliance report
GET  /api/v1/anomalies/compliance/score   Overall score
```

### WebSocket
```
WS /ws/jobs/{job_id}   Live job progress stream
```

## Policy format

Policies are defined in YAML and attached to data sources:

```yaml
frequency_minutes: 360       # back up every 6 hours
retention_days: 90           # keep snapshots for 90 days
rpo_minutes: 720             # alert if no backup in 12 hours
require_checksum: true       # enforce SHA-256 verification
require_dedup: true          # enforce deduplication
entropy_threshold: 7.2       # ransomware alert threshold (bits/byte)
```

## Compliance

BackupOS maps policy attributes to framework controls:

| Framework | Applies to | Key controls |
|---|---|---|
| SOC 2 | All sources | Retention ≥30d, checksum, RPO ≤24h, no critical alerts |
| HIPAA | PII classification | Checksum + dedup + retention ≥365d |
| PCI-DSS | Financial classification | Retention ≥365d + daily backup frequency |

## Running tests

```bash
pip install -r requirements.txt
pytest tests/ -v --cov=app --cov-report=term-missing
```

## Demo

With the stack running (`docker-compose up`), run the end-to-end demo:

```bash
python scripts/demo.py
```

The demo registers a tenant, creates a source and policy, runs two backups (full then incremental), checks recovery metrics, and prints the compliance report.
