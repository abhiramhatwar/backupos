#!/usr/bin/env python3
"""
BackupOS end-to-end demo & dashboard seeder.

Populates a fresh BackupOS instance with realistic data so the dashboard at
http://localhost:8000 looks fully alive: two data sources, a backup policy,
several incremental snapshots (showing real deduplication), a growth trend
for the analytics chart, and a *simulated ransomware attack* that trips the
entropy-spike and dedup-ratio-collapse detectors.

Run it INSIDE the api container so it shares the code bind-mount with the
Celery worker (this is what makes the backed-up files visible to the worker):

    docker-compose exec api python scripts/demo.py

It also works from the host if httpx is installed, because the demo data is
written under the repo directory, which is bind-mounted to /app in both the
api and worker containers.

Login afterwards with:
    email    : demo@backupos.local
    password : demo-password-123
"""
import os
import sys
import time

try:
    import httpx
except ImportError:
    sys.exit("httpx is required. Run inside the container:\n"
             "    docker-compose exec api python scripts/demo.py")

BASE_URL = os.getenv("BACKUPOS_URL", "http://localhost:8000/api/v1")
MAX_POLL_SECONDS = 120

DEMO_EMAIL = "demo@backupos.io"
DEMO_PASSWORD = "demo-password-123"

# The demo writes files under <repo>/demo_data on whatever machine runs this
# script.  Because <repo> is bind-mounted to /app inside the containers, the
# worker always reads the files at /app/demo_data — so we register that path.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_LOCAL_DATA = os.path.join(_REPO_ROOT, "demo_data")   # where THIS process writes
_CONTAINER_DATA = "/app/demo_data"                    # what the worker reads


# ---------------------------------------------------------------------------
# pretty output
# ---------------------------------------------------------------------------
def banner(msg): print("\n" + "=" * 64 + f"\n  {msg}\n" + "=" * 64)
def step(msg):   print(f"\n▶ {msg}")
def ok(msg):     print(f"  ✓ {msg}")
def info(msg):   print(f"    {msg}")
def fail(resp):
    print(f"  ✗ HTTP {resp.status_code}: {resp.text}")
    sys.exit(1)


# ---------------------------------------------------------------------------
# data generators
# ---------------------------------------------------------------------------
def local_path(rel):     return os.path.join(_LOCAL_DATA, rel)
def container_path(rel): return f"{_CONTAINER_DATA}/{rel}"


def write_text_files(rel_dir, n, salt=""):
    """Low-entropy text files (~4-5 bits/byte) — the 'normal' baseline."""
    d = local_path(rel_dir)
    os.makedirs(d, exist_ok=True)
    for i in range(n):
        with open(os.path.join(d, f"record_{i:02d}.txt"), "w") as f:
            f.write(f"BackupOS customer record {i}{salt}\n")
            f.write("name: Jane Doe\nplan: enterprise\nregion: us-east-1\n")
            f.write(("data field with repeating content, " * 20 + "\n") * 8)


def encrypt_in_place(rel_dir):
    """Overwrite every file with random bytes — entropy ~8.0, mimics ransomware."""
    d = local_path(rel_dir)
    for fname in os.listdir(d):
        fpath = os.path.join(d, fname)
        if os.path.isfile(fpath):
            size = os.path.getsize(fpath)
            with open(fpath, "wb") as f:
                f.write(os.urandom(max(size, 4096)))
        # Ransomware calling card
    with open(os.path.join(d, "READ_ME_TO_DECRYPT.txt"), "wb") as f:
        f.write(os.urandom(2048))


# ---------------------------------------------------------------------------
# api helpers
# ---------------------------------------------------------------------------
def run_backup(client, headers, source_id, backup_type):
    resp = client.post("/backups", json={"source_id": source_id, "backup_type": backup_type}, headers=headers)
    if resp.status_code not in (200, 201):
        fail(resp)
    job = resp.json()
    job_id = job["id"]
    deadline = time.time() + MAX_POLL_SECONDS
    while time.time() < deadline:
        r = client.get(f"/backups/{job_id}", headers=headers)
        if r.status_code != 200:
            break
        job = r.json()
        print(f"    job #{job_id} [{backup_type}] status={job['status']}   ", end="\r")
        if job["status"] in ("completed", "failed"):
            break
        time.sleep(2)
    print()
    return job


def latest_snapshot(client, headers, source_id):
    r = client.get(f"/backups/{source_id}/history?limit=1", headers=headers)
    if r.status_code == 200 and r.json():
        return r.json()[0]
    return None


# ===========================================================================
banner("BackupOS — Demo & Dashboard Seeder")
client = httpx.Client(base_url=BASE_URL, timeout=60)

# 1. tenant --------------------------------------------------------------
step("Registering demo tenant")
resp = client.post("/auth/register", json={"name": "Demo Corp", "email": DEMO_EMAIL, "password": DEMO_PASSWORD})
if resp.status_code in (200, 201):
    ok(f"Registered {DEMO_EMAIL}")
elif resp.status_code == 400 and "already registered" in resp.text:
    ok("Tenant already exists — continuing")
else:
    fail(resp)

resp = client.post("/auth/token", json={"email": DEMO_EMAIL, "password": DEMO_PASSWORD})
if resp.status_code != 200:
    fail(resp)
headers = {"Authorization": f"Bearer {resp.json()['access_token']}"}
ok("Authenticated")

# 2. policy --------------------------------------------------------------
step("Creating & attaching backup policy")
policy_yaml = ("frequency_minutes: 60\nretention_days: 30\nrpo_minutes: 120\n"
               "require_checksum: true\nrequire_dedup: true\nentropy_threshold: 7.5\n")
resp = client.post("/policies", json={"name": "Tier-1 Critical", "description": "60-min RPO, 30-day retention",
                                      "policy_yaml": policy_yaml}, headers=headers)
if resp.status_code not in (200, 201):
    fail(resp)
policy_id = resp.json()["id"]
ok(f"Policy #{policy_id} created (RPO 120m, entropy threshold 7.5)")

# helper to create (or reuse) a source by name
existing = {s["name"]: s for s in client.get("/sources", headers=headers).json()}


def ensure_source(name, rel_dir, classification):
    if name in existing:
        ok(f"Source '{name}' already exists (#{existing[name]['id']})")
        return existing[name]["id"]
    resp = client.post("/sources", json={
        "name": name, "source_type": "directory", "path": container_path(rel_dir),
        "classification": classification, "tags": {"env": "demo"},
    }, headers=headers)
    if resp.status_code not in (200, 201):
        fail(resp)
    sid = resp.json()["id"]
    ok(f"Source '{name}' created (#{sid}) → {container_path(rel_dir)}")
    client.post(f"/policies/{policy_id}/attach", json={"source_id": sid}, headers=headers)
    return sid


# 3. SOURCE A — healthy source with a clean growth trend -----------------
banner("Source A — Production Documents (healthy)")
write_text_files("prod_docs", n=8)
src_a = ensure_source("Production Documents", "prod_docs", "confidential")

step("Full backup (establishes baseline)")
run_backup(client, headers, src_a, "full")

for round_no in range(1, 4):
    step(f"Incremental #{round_no} (add a file + small edits → high dedup)")
    write_text_files("prod_docs", n=8 + round_no, salt=f" v{round_no}")  # mostly-identical data
    job = run_backup(client, headers, src_a, "incremental")
    snap = latest_snapshot(client, headers, src_a)
    if snap:
        info(f"snapshot #{snap['id']}  dedup={snap['dedup_ratio']*100:.0f}%  "
             f"entropy={snap['average_entropy']:.2f}  chunks={snap['chunk_count']} (+{snap['new_chunk_count']})")

# 4. SOURCE B — clean history, then a ransomware attack ------------------
banner("Source B — Customer DB Exports (about to be attacked)")
write_text_files("db_exports", n=10)
src_b = ensure_source("Customer DB Exports", "db_exports", "pii")

step("Full backup (clean baseline)")
run_backup(client, headers, src_b, "full")

for round_no in range(1, 4):
    step(f"Incremental #{round_no} (normal daily backup)")
    write_text_files("db_exports", n=10, salt=f" day{round_no}")
    run_backup(client, headers, src_b, "incremental")
    snap = latest_snapshot(client, headers, src_b)
    if snap:
        info(f"snapshot #{snap['id']}  dedup={snap['dedup_ratio']*100:.0f}%  entropy={snap['average_entropy']:.2f}")

step("🔒 SIMULATING RANSOMWARE — encrypting all files in place")
encrypt_in_place("db_exports")
ok("Files overwritten with random (encrypted) bytes")

step("Nightly incremental backup runs against the encrypted data…")
run_backup(client, headers, src_b, "incremental")
snap = latest_snapshot(client, headers, src_b)
if snap:
    info(f"snapshot #{snap['id']}  dedup={snap['dedup_ratio']*100:.0f}%  "
         f"entropy={snap['average_entropy']:.2f} bits/byte  ← SPIKE")

# 5. show what the detectors caught -------------------------------------
banner("Detection Results")
alerts = client.get("/anomalies", headers=headers).json()
if alerts:
    ok(f"{len(alerts)} anomaly alert(s) raised:")
    for a in alerts:
        info(f"[{a['severity'].upper():8}] {a['alert_type']}: {a['detail']}")
else:
    info("No alerts raised (unexpected — check worker logs).")

# 6. recovery metrics + compliance --------------------------------------
banner("Recovery & Compliance")
m = client.get(f"/backups/{src_b}/recovery-metrics", headers=headers).json()
ok(f"Source B — RPO now {m.get('current_rpo_minutes', 0):.1f}m "
   f"(limit {m.get('policy_rpo_minutes')}m, violated={m.get('rpo_violated')}), "
   f"{m.get('total_snapshots')} snapshots, est. RTO {m.get('estimated_rto_minutes')}m")

report = client.get("/anomalies/compliance/report", headers=headers).json()
ok(f"Overall compliance score: {report['overall_score']:.1f}/100 "
   f"({report['total_violations']} violations, {report['critical_alerts']} critical alerts)")
for s in report["sources"]:
    info(f"{s['source_name']}: overall={s['overall_score']:.0f} "
         f"SOC2={s['soc2_score']:.0f} HIPAA={s['hipaa_score']:.0f} PCI={s['pci_score']:.0f}")

# ---------------------------------------------------------------------------
banner("Demo Complete — open the dashboard")
print(f"""
  Dashboard : http://localhost:8000
  Login     : {DEMO_EMAIL}  /  {DEMO_PASSWORD}

  What to look at:
    • Overview    — stat cards + compliance gauge
    • Snapshots   — pick 'Production Documents', watch dedup % climb
    • Analytics   — dedup-vs-raw growth chart + capacity projection
    • Ransomware  — entropy meter pinned high + critical alerts
    • Compliance  — SOC2 / HIPAA / PCI scores per source
""")
