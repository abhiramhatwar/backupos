#!/usr/bin/env python3
"""
BackupOS end-to-end demo.

Runs against the live API at http://localhost:8000.
Start the stack first:
    docker-compose up -d

Then run:
    python scripts/demo.py
"""
import os
import sys
import time
import textwrap

import httpx

BASE_URL = "http://localhost:8000/api/v1"
DEMO_DATA_DIR = "/tmp/demo_data"
MAX_POLL_SECONDS = 120


def banner(msg: str) -> None:
    print("\n" + "=" * 60)
    print(f"  {msg}")
    print("=" * 60)


def step(n: int, msg: str) -> None:
    print(f"\n[{n}] {msg}")


def ok(msg: str) -> None:
    print(f"    OK  {msg}")


def fail(resp: httpx.Response) -> None:
    print(f"    FAIL  HTTP {resp.status_code}: {resp.text}")
    sys.exit(1)


# ---------------------------------------------------------------------------
# 1. Register tenant and get a token
# ---------------------------------------------------------------------------
banner("BackupOS End-to-End Demo")

step(1, "Registering tenant …")
client = httpx.Client(base_url=BASE_URL, timeout=30)

reg_payload = {
    "name": "Demo Corp",
    "email": "demo@backupos.local",
    "password": "demo-password-123",
}
resp = client.post("/auth/register", json=reg_payload)
if resp.status_code not in (200, 201, 400):  # 400 = already registered
    fail(resp)

if resp.status_code == 400 and "already registered" in resp.text:
    ok("Tenant already exists, continuing …")
else:
    ok(f"Registered: {resp.json()['email']}")

# ---------------------------------------------------------------------------
# 2. Login and obtain JWT token
# ---------------------------------------------------------------------------
step(2, "Logging in …")
resp = client.post("/auth/token", json={"email": reg_payload["email"], "password": reg_payload["password"]})
if resp.status_code != 200:
    fail(resp)

token = resp.json()["access_token"]
auth_headers = {"Authorization": f"Bearer {token}"}
ok(f"Token obtained (first 20 chars): {token[:20]}…")

# ---------------------------------------------------------------------------
# 3. Create a data source
# ---------------------------------------------------------------------------
step(3, "Creating data source …")
resp = client.post(
    "/sources",
    json={
        "name": "Demo Files",
        "source_type": "directory",
        "path": DEMO_DATA_DIR,
        "classification": "internal",
        "tags": {"env": "demo"},
    },
    headers=auth_headers,
)
if resp.status_code not in (200, 201):
    fail(resp)

source = resp.json()
source_id = source["id"]
ok(f"Data source created: id={source_id}, path={source['path']}")

# ---------------------------------------------------------------------------
# 4. Create and attach a backup policy
# ---------------------------------------------------------------------------
step(4, "Creating backup policy …")
policy_yaml = textwrap.dedent("""\
    frequency_minutes: 60
    retention_days: 30
    rpo_minutes: 120
    require_checksum: true
    require_dedup: true
    entropy_threshold: 7.5
""")
resp = client.post(
    "/policies",
    json={"name": "Demo Policy", "description": "Demo backup policy", "policy_yaml": policy_yaml},
    headers=auth_headers,
)
if resp.status_code not in (200, 201):
    fail(resp)

policy = resp.json()
policy_id = policy["id"]
ok(f"Policy created: id={policy_id}, frequency={policy['frequency_minutes']}m, RPO={policy['rpo_minutes']}m")

step(4, "Attaching policy to source …")
resp = client.post(
    f"/policies/{policy_id}/attach",
    json={"source_id": source_id},
    headers=auth_headers,
)
if resp.status_code not in (200, 201, 409):  # 409 = already attached
    fail(resp)
ok(f"Policy {policy_id} attached to source {source_id}")

# ---------------------------------------------------------------------------
# 5. Create demo data files
# ---------------------------------------------------------------------------
step(5, "Creating demo data in /tmp/demo_data …")
os.makedirs(DEMO_DATA_DIR, exist_ok=True)
for i in range(5):
    fpath = os.path.join(DEMO_DATA_DIR, f"file_{i:02d}.txt")
    with open(fpath, "w") as f:
        # ~5KB of content per file
        f.write(f"BackupOS demo file {i}\n" + ("x" * 100 + "\n") * 50)
ok(f"Created 5 files in {DEMO_DATA_DIR}")

# ---------------------------------------------------------------------------
# 6. Trigger full backup job
# ---------------------------------------------------------------------------
step(6, "Triggering full backup …")
resp = client.post(
    "/backups",
    json={"source_id": source_id, "backup_type": "full"},
    headers=auth_headers,
)
if resp.status_code not in (200, 201):
    fail(resp)

job = resp.json()
job_id = job["id"]
ok(f"Backup job created: id={job_id}, status={job['status']}")

# ---------------------------------------------------------------------------
# 7. Poll job status until complete
# ---------------------------------------------------------------------------
step(7, "Polling backup job status …")
deadline = time.time() + MAX_POLL_SECONDS
while time.time() < deadline:
    resp = client.get(f"/backups/{job_id}", headers=auth_headers)
    if resp.status_code != 200:
        fail(resp)
    job = resp.json()
    print(f"    status={job['status']}", end="\r")
    if job["status"] in ("completed", "failed"):
        break
    time.sleep(3)
print()
ok(f"Job finished with status: {job['status']}")

# ---------------------------------------------------------------------------
# 8. Get recovery metrics
# ---------------------------------------------------------------------------
step(8, "Fetching recovery metrics …")
resp = client.get(f"/backups/{source_id}/recovery-metrics", headers=auth_headers)
if resp.status_code != 200:
    fail(resp)

metrics = resp.json()
ok(f"RPO: {metrics['current_rpo_minutes']} min (limit: {metrics['policy_rpo_minutes']} min)")
ok(f"RPO violated: {metrics['rpo_violated']}")
ok(f"Estimated RTO: {metrics['estimated_rto_minutes']} min")
ok(f"Total snapshots: {metrics['total_snapshots']}")

# ---------------------------------------------------------------------------
# 9. Trigger incremental backup
# ---------------------------------------------------------------------------
step(9, "Triggering incremental backup …")
# Modify one file to create a real diff
with open(os.path.join(DEMO_DATA_DIR, "file_00.txt"), "a") as f:
    f.write("\nNew data appended for incremental backup test.\n" + "y" * 200)

resp = client.post(
    "/backups",
    json={"source_id": source_id, "backup_type": "incremental"},
    headers=auth_headers,
)
if resp.status_code not in (200, 201):
    fail(resp)

inc_job = resp.json()
inc_job_id = inc_job["id"]
ok(f"Incremental backup job created: id={inc_job_id}")

# Poll
deadline = time.time() + MAX_POLL_SECONDS
while time.time() < deadline:
    resp = client.get(f"/backups/{inc_job_id}", headers=auth_headers)
    if resp.status_code != 200:
        break
    inc_job = resp.json()
    print(f"    status={inc_job['status']}", end="\r")
    if inc_job["status"] in ("completed", "failed"):
        break
    time.sleep(3)
print()
ok(f"Incremental job finished with status: {inc_job['status']}")

# ---------------------------------------------------------------------------
# 10. Get compliance report
# ---------------------------------------------------------------------------
step(10, "Generating compliance report …")
resp = client.get("/anomalies/compliance/report", headers=auth_headers)
if resp.status_code != 200:
    fail(resp)

report = resp.json()
ok(f"Overall compliance score: {report['overall_score']:.1f} / 100")
ok(f"Total violations: {report['total_violations']}")
ok(f"Critical alerts: {report['critical_alerts']}")
for s in report["sources"]:
    ok(f"  Source '{s['source_name']}': overall={s['overall_score']:.1f} SOC2={s['soc2_score']:.1f} HIPAA={s['hipaa_score']:.1f} PCI={s['pci_score']:.1f}")
    for v in s["violations"]:
        print(f"       - {v}")

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
banner("Demo Complete")
print(f"  Source ID       : {source_id}")
print(f"  Full backup job : {job_id}  ({job['status']})")
print(f"  Incr backup job : {inc_job_id}  ({inc_job['status']})")
print(f"  Compliance score: {report['overall_score']:.1f}/100")
print()
