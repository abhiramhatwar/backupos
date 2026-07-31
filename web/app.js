/* BackupOS dashboard — vanilla JS SPA against the FastAPI backend. */

const API = "/api/v1";
let TOKEN = localStorage.getItem("bos_token") || null;
let SOURCES = [];        // cached source list
let POLICIES = [];       // cached policy list
let anChart = null;      // Chart.js instance
const wsConns = {};      // job_id -> WebSocket

/* ---------- helpers ---------- */
function authHeaders(extra = {}) {
  const h = { ...extra };
  if (TOKEN) h["Authorization"] = "Bearer " + TOKEN;
  return h;
}

async function api(path, { method = "GET", body = null, raw = false } = {}) {
  const opts = { method, headers: authHeaders() };
  if (body !== null) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(API + path, opts);
  if (res.status === 401) { logout(); throw new Error("Session expired — sign in again."); }
  if (!res.ok) {
    let detail = res.statusText;
    try { const j = await res.json(); detail = j.detail || JSON.stringify(j); } catch (_) {}
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  if (res.status === 204) return null;
  return raw ? res : res.json();
}

function toast(msg, kind = "ok") {
  const colors = { ok: "background:#059669;color:#fff", err: "background:#dc2626;color:#fff", info: "background:#1e293b;color:#e2e8f0" };
  const el = document.createElement("div");
  el.className = "toast"; el.setAttribute("style", colors[kind] || colors.ok);
  el.textContent = msg;
  document.getElementById("toast-container").appendChild(el);
  setTimeout(() => el.remove(), 3200);
}

function fmtBytes(b) {
  if (b == null) return "—";
  if (b === 0) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"]; const i = Math.floor(Math.log(b) / Math.log(1024));
  return (b / Math.pow(1024, i)).toFixed(i ? 1 : 0) + " " + u[i];
}
function fmtTime(t) { if (!t) return "—"; const d = new Date(t); return d.toLocaleString(); }
function shortHash(h) { return h ? h.slice(0, 10) + "…" : "—"; }
function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }

const STATUS_BADGE = {
  pending:   "background:#334155;color:#cbd5e1",
  running:   "background:#1d4ed8;color:#fff",
  verifying: "background:#7c3aed;color:#fff",
  completed: "background:#059669;color:#fff",
  failed:    "background:#dc2626;color:#fff",
};
const SEV_BADGE = {
  low:      "background:#334155;color:#cbd5e1",
  medium:   "background:#ca8a04;color:#fff",
  high:     "background:#ea580c;color:#fff",
  critical: "background:#dc2626;color:#fff",
};

/* ---------- auth ---------- */
let authMode = "login";
function switchAuth(mode) {
  authMode = mode;
  document.getElementById("auth-tab-login").classList.toggle("active", mode === "login");
  document.getElementById("auth-tab-register").classList.toggle("active", mode === "register");
  document.getElementById("reg-name-field").classList.toggle("hidden", mode !== "register");
  document.getElementById("auth-submit").textContent = mode === "login" ? "Sign In" : "Create Account";
  document.getElementById("auth-error").classList.add("hidden");
}

document.getElementById("auth-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const errEl = document.getElementById("auth-error");
  errEl.classList.add("hidden");
  const email = document.getElementById("auth-email").value.trim();
  const password = document.getElementById("auth-password").value;
  const name = document.getElementById("auth-name").value.trim();
  try {
    if (authMode === "register") {
      if (!name) throw new Error("Organization name is required.");
      await api("/auth/register", { method: "POST", body: { name, email, password } });
      toast("Account created — signing in…");
    }
    const res = await fetch(API + "/auth/token", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    if (!res.ok) { const j = await res.json().catch(() => ({})); throw new Error(j.detail || "Invalid credentials"); }
    const data = await res.json();
    TOKEN = data.access_token;
    localStorage.setItem("bos_token", TOKEN);
    await enterApp();
  } catch (err) {
    errEl.textContent = err.message; errEl.classList.remove("hidden");
  }
});

function logout() {
  TOKEN = null; localStorage.removeItem("bos_token");
  Object.values(wsConns).forEach(ws => { try { ws.close(); } catch (_) {} });
  document.getElementById("app-screen").classList.add("hidden");
  document.getElementById("auth-screen").classList.remove("hidden");
}

async function enterApp() {
  document.getElementById("auth-screen").classList.add("hidden");
  document.getElementById("app-screen").classList.remove("hidden");
  try {
    const me = await api("/auth/me");
    document.getElementById("tenant-label").textContent = `${me.name} · ${me.email}`;
  } catch (_) {}
  await refreshAll();
}

/* ---------- tabs ---------- */
const TABS = ["overview", "sources", "backups", "snapshots", "analytics", "ransomware", "policies", "compliance"];
function switchTab(tab) {
  TABS.forEach(t => document.getElementById("tab-" + t).classList.toggle("hidden", t !== tab));
  document.querySelectorAll("#app-screen .tab-btn").forEach(b =>
    b.classList.toggle("active", b.getAttribute("onclick") === `switchTab('${tab}')`));
  if (tab === "overview")   loadOverview();
  if (tab === "sources")    loadSources();
  if (tab === "backups")    { populateSourceSelects(); loadBackups(); }
  if (tab === "snapshots")  populateSourceSelects();
  if (tab === "analytics")  populateSourceSelects();
  if (tab === "ransomware") { loadAnomalies(); loadEntropy(); }
  if (tab === "policies")   { loadPolicies(); populateSourceSelects(); }
  if (tab === "compliance") { /* on demand */ }
}

async function refreshAll() {
  await checkHealth();
  await loadSourcesData();
  loadOverview();
  const active = document.querySelector("#app-screen .tab-btn.active");
  if (active) active.click();
}

async function checkHealth() {
  try {
    const r = await fetch("/health"); const j = await r.json();
    const ok = j.status === "ok";
    document.getElementById("health-dot").style.background = ok ? "#22c55e" : "#ef4444";
    document.getElementById("health-label").textContent = ok ? "API healthy" : "API down";
  } catch (_) {
    document.getElementById("health-dot").style.background = "#ef4444";
    document.getElementById("health-label").textContent = "API down";
  }
}

/* ---------- data loading ---------- */
async function loadSourcesData() {
  try { SOURCES = await api("/sources"); } catch (_) { SOURCES = []; }
}

function populateSourceSelects() {
  const opts = SOURCES.length
    ? SOURCES.map(s => `<option value="${s.id}">${esc(s.name)} (#${s.id})</option>`).join("")
    : `<option value="">— no sources —</option>`;
  ["bk-source", "snap-source", "an-source", "attach-source"].forEach(id => {
    const el = document.getElementById(id); if (el) el.innerHTML = opts;
  });
}

/* ---------- Overview ---------- */
async function loadOverview() {
  await loadSourcesData();
  let backups = [], snapCount = 0, alerts = [];
  try { backups = await api("/backups?limit=200"); } catch (_) {}
  try { alerts = await api("/anomalies"); } catch (_) {}
  // count snapshots across sources via history
  for (const s of SOURCES) {
    try { const h = await api(`/backups/${s.id}/history?limit=200`); snapCount += h.length; } catch (_) {}
  }
  document.getElementById("ov-sources").textContent = SOURCES.length;
  document.getElementById("ov-backups").textContent = backups.length;
  document.getElementById("ov-snapshots").textContent = snapCount;
  document.getElementById("ov-alerts").textContent = alerts.length;

  // compliance gauge
  try {
    const c = await api("/anomalies/compliance/score");
    const score = Math.round(c.overall_score || 0);
    const arc = document.getElementById("comp-arc");
    const dash = 251;
    arc.style.strokeDashoffset = dash - (dash * score / 100);
    arc.setAttribute("stroke", score >= 80 ? "#22c55e" : score >= 55 ? "#eab308" : "#ef4444");
    document.getElementById("comp-score").textContent = score;
    document.getElementById("comp-sub").textContent = `${c.source_count} source(s) evaluated`;
  } catch (_) {}

  // recent jobs
  const recent = backups.slice(0, 6);
  document.getElementById("ov-recent").innerHTML = recent.length ? `
    <table><thead><tr><th>Job</th><th>Source</th><th>Type</th><th>Status</th><th>Created</th></tr></thead>
    <tbody>${recent.map(j => `
      <tr><td class="mono">#${j.id}</td><td>${sourceName(j.source_id)}</td>
      <td>${j.backup_type}</td>
      <td><span class="badge" style="${STATUS_BADGE[j.status] || ''}">${j.status}</span></td>
      <td class="text-slate-500">${fmtTime(j.created_at)}</td></tr>`).join("")}</tbody></table>`
    : `<div class="text-slate-500 text-sm">No jobs yet — trigger one from the Backups tab.</div>`;
}

function sourceName(id) { const s = SOURCES.find(x => x.id === id); return s ? esc(s.name) : `#${id}`; }

/* ---------- Sources ---------- */
async function loadSources() {
  await loadSourcesData();
  const el = document.getElementById("sources-list");
  if (!SOURCES.length) { el.innerHTML = `<div class="text-slate-500 text-sm">No sources yet. Register one above.</div>`; return; }
  el.innerHTML = `<table><thead><tr><th>ID</th><th>Name</th><th>Type</th><th>Path</th><th>Classification</th><th></th></tr></thead>
    <tbody>${SOURCES.map(s => `
      <tr><td class="mono">#${s.id}</td><td class="text-white">${esc(s.name)}</td>
      <td>${s.source_type}</td><td class="mono text-slate-400">${esc(s.path)}</td>
      <td><span class="badge" style="background:#1e293b;color:#93c5fd">${s.classification}</span></td>
      <td class="text-right"><button onclick="deleteSource(${s.id})" class="text-red-400 hover:text-red-300 text-xs">delete</button></td></tr>`).join("")}
    </tbody></table>`;
}

async function createSource() {
  const name = document.getElementById("src-name").value.trim();
  const path = document.getElementById("src-path").value.trim();
  const source_type = document.getElementById("src-type").value;
  const classification = document.getElementById("src-class").value;
  if (!name || !path) return toast("Name and path are required.", "err");
  try {
    await api("/sources", { method: "POST", body: { name, path, source_type, classification, tags: {} } });
    toast("Source registered.");
    document.getElementById("src-name").value = ""; document.getElementById("src-path").value = "";
    await loadSources(); populateSourceSelects();
  } catch (e) { toast(e.message, "err"); }
}

async function deleteSource(id) {
  if (!confirm("Delete this source and all its backups?")) return;
  try { await api(`/sources/${id}`, { method: "DELETE" }); toast("Source deleted."); await loadSources(); populateSourceSelects(); }
  catch (e) { toast(e.message, "err"); }
}

/* ---------- Backups + live WS progress ---------- */
async function triggerBackup() {
  const source_id = parseInt(document.getElementById("bk-source").value, 10);
  const backup_type = document.getElementById("bk-type").value;
  if (!source_id) return toast("Pick a source first.", "err");
  try {
    const job = await api("/backups", { method: "POST", body: { source_id, backup_type } });
    toast(`Backup job #${job.id} dispatched.`);
    await loadBackups();
  } catch (e) { toast(e.message, "err"); }
}

async function loadBackups() {
  let jobs = [];
  try { jobs = await api("/backups?limit=100"); } catch (e) { document.getElementById("backups-list").innerHTML = `<div class="text-red-400 text-sm">${esc(e.message)}</div>`; return; }
  const el = document.getElementById("backups-list");
  if (!jobs.length) { el.innerHTML = `<div class="text-slate-500 text-sm">No backup jobs yet.</div>`; return; }
  el.innerHTML = `<table><thead><tr><th>Job</th><th>Source</th><th>Type</th><th>Status</th><th style="width:160px">Progress</th><th>Created</th></tr></thead>
    <tbody>${jobs.map(j => `
      <tr id="job-row-${j.id}">
        <td class="mono">#${j.id}</td><td>${sourceName(j.source_id)}</td><td>${j.backup_type}</td>
        <td><span class="badge" id="job-status-${j.id}" style="${STATUS_BADGE[j.status] || ''}">${j.status}</span></td>
        <td><div class="progress-track"><div class="progress-fill" id="job-prog-${j.id}" style="width:0%"></div></div></td>
        <td class="text-slate-500">${fmtTime(j.created_at)}</td>
      </tr>`).join("")}</tbody></table>`;
  // open WS for non-terminal jobs
  jobs.forEach(j => {
    const term = j.status === "completed" || j.status === "failed";
    const fill = document.getElementById(`job-prog-${j.id}`);
    if (term) { fill.style.width = j.status === "completed" ? "100%" : "0%"; fill.style.background = j.status === "failed" ? "#dc2626" : "#22c55e"; }
    else watchJob(j.id);
  });
}

function watchJob(jobId) {
  if (wsConns[jobId]) return;
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws/jobs/${jobId}`);
  wsConns[jobId] = ws;
  ws.onmessage = (ev) => {
    let d; try { d = JSON.parse(ev.data); } catch (_) { return; }
    const fill = document.getElementById(`job-prog-${jobId}`);
    const badge = document.getElementById(`job-status-${jobId}`);
    if (fill) {
      fill.style.width = Math.round((d.progress || 0) * 100) + "%";
      if (d.status === "failed") fill.style.background = "#dc2626";
      if (d.status === "completed") fill.style.background = "#22c55e";
    }
    if (badge && STATUS_BADGE[d.status]) { badge.textContent = d.status; badge.setAttribute("style", STATUS_BADGE[d.status]); }
    if (d.status === "completed" || d.status === "failed" || d.status === "not_found") {
      ws.close(); delete wsConns[jobId];
      if (d.status === "completed") toast(`Job #${jobId} completed.`);
      if (d.status === "failed") toast(`Job #${jobId} failed.`, "err");
      loadOverview();
    }
  };
  ws.onclose = () => { delete wsConns[jobId]; };
  ws.onerror = () => { try { ws.close(); } catch (_) {} delete wsConns[jobId]; };
}

/* ---------- Snapshots ---------- */
async function loadSnapshots() {
  const sid = parseInt(document.getElementById("snap-source").value, 10);
  if (!sid) return;
  const listEl = document.getElementById("snapshots-list");
  const metricsEl = document.getElementById("recovery-metrics");
  listEl.innerHTML = `<div class="text-slate-500 text-sm">Loading…</div>`;
  // recovery metrics
  try {
    const m = await api(`/backups/${sid}/recovery-metrics`);
    const card = (label, val, color = "text-white") => `<div class="card p-3"><div class="text-lg font-bold ${color}">${val}</div><div class="text-slate-500 text-xs mt-0.5">${label}</div></div>`;
    metricsEl.innerHTML =
      card("Total Snapshots", m.total_snapshots) +
      card("RPO (min)", m.current_rpo_minutes != null ? m.current_rpo_minutes.toFixed(1) : "—", m.rpo_violated ? "text-red-400" : "text-emerald-400") +
      card("Est. RTO (min)", m.estimated_rto_minutes != null ? m.estimated_rto_minutes.toFixed(2) : "—") +
      card("Last Backup", m.last_successful_backup ? fmtTime(m.last_successful_backup) : "—", "text-white text-xs");
  } catch (_) { metricsEl.innerHTML = ""; }
  // history
  try {
    const snaps = await api(`/backups/${sid}/history?limit=100`);
    if (!snaps.length) { listEl.innerHTML = `<div class="text-slate-500 text-sm">No snapshots. Run a backup for this source.</div>`; return; }
    listEl.innerHTML = `<table><thead><tr><th>ID</th><th>Merkle Root</th><th>Size</th><th>Dedup</th><th>Chunks</th><th>Entropy</th><th>Created</th><th></th></tr></thead>
      <tbody>${snaps.map(s => `
        <tr><td class="mono">#${s.id}</td>
        <td class="mono text-slate-400" title="${s.merkle_root}">${shortHash(s.merkle_root)}</td>
        <td>${fmtBytes(s.total_size_bytes)}</td>
        <td><span class="text-emerald-400">${(s.dedup_ratio * 100).toFixed(1)}%</span></td>
        <td>${s.chunk_count} <span class="text-slate-600">(+${s.new_chunk_count})</span></td>
        <td>${s.average_entropy.toFixed(2)}</td>
        <td class="text-slate-500">${fmtTime(s.created_at)}</td>
        <td class="text-right whitespace-nowrap">
          <button onclick="verifySnapshot(${sid},${s.id})" class="text-blue-400 hover:text-blue-300 text-xs">verify</button>
          <button onclick="lockSnapshot(${s.id})" class="text-amber-400 hover:text-amber-300 text-xs ml-2">${s.locked_until ? "🔒" : "lock"}</button>
        </td></tr>`).join("")}</tbody></table>`;
  } catch (e) { listEl.innerHTML = `<div class="text-red-400 text-sm">${esc(e.message)}</div>`; }
}

async function verifySnapshot(sid, snapId) {
  try {
    const r = await api(`/restore/${sid}/verify/${snapId}`);
    toast(r.is_valid ? `Snapshot #${snapId} verified ✓ (${r.chunk_count} chunks, Merkle root matches)` : `Snapshot #${snapId} INTEGRITY FAILURE`, r.is_valid ? "ok" : "err");
  } catch (e) { toast(e.message, "err"); }
}

async function lockSnapshot(snapId) {
  try { await api(`/snapshots/${snapId}/lock`, { method: "POST", body: { lock_days: 30 } }); toast(`Snapshot #${snapId} WORM-locked for 30 days.`); loadSnapshots(); }
  catch (e) { toast(e.message, "err"); }
}

/* ---------- Analytics ---------- */
async function loadAnalytics() {
  const sid = parseInt(document.getElementById("an-source").value, 10);
  if (!sid) return;
  let a;
  try { a = await api(`/analytics/sources/${sid}`); } catch (e) { toast(e.message, "err"); return; }
  const card = (label, val, color = "text-white") => `<div class="card p-4"><div class="text-2xl font-bold ${color}">${val}</div><div class="text-slate-400 text-xs mt-1">${label}</div></div>`;
  document.getElementById("an-stats").innerHTML =
    card("Snapshots", a.snapshot_count) +
    card("Unique Stored", fmtBytes(a.total_unique_bytes), "text-emerald-400") +
    card("Raw (pre-dedup)", fmtBytes(a.total_raw_bytes), "text-blue-400") +
    card("Dedup Ratio", (a.overall_dedup_ratio * 100).toFixed(1) + "%", "text-emerald-400");

  const labels = a.trends.map(t => "#" + t.snapshot_id);
  const raw = a.trends.map(t => t.total_size_bytes);
  const dedup = a.trends.map(t => t.dedup_size_bytes);
  if (anChart) anChart.destroy();
  anChart = new Chart(document.getElementById("an-chart"), {
    type: "line",
    data: { labels, datasets: [
      { label: "Raw size", data: raw, borderColor: "#3b82f6", backgroundColor: "rgba(59,130,246,.1)", fill: true, tension: .3 },
      { label: "Deduplicated", data: dedup, borderColor: "#22c55e", backgroundColor: "rgba(34,197,94,.1)", fill: true, tension: .3 },
    ]},
    options: { responsive: true, plugins: { legend: { labels: { color: "#94a3b8" } } },
      scales: { x: { ticks: { color: "#64748b" }, grid: { color: "#1e293b" } },
                y: { ticks: { color: "#64748b", callback: v => fmtBytes(v) }, grid: { color: "#1e293b" } } } },
  });

  const p = a.growth_projection;
  document.getElementById("an-projection").innerHTML = p
    ? `Growth: <span class="text-white">${fmtBytes(p.slope_bytes_per_day)}/day</span> · 30d → <span class="text-white">${fmtBytes(p.projected_30d_bytes)}</span> · 90d → <span class="text-white">${fmtBytes(p.projected_90d_bytes)}</span> · R²=${p.r_squared} (${p.data_points} points)`
    : `Need ≥2 snapshots for a growth projection.`;
}

/* ---------- Ransomware / anomalies ---------- */
async function loadAnomalies() {
  const el = document.getElementById("anomalies-list");
  try {
    const alerts = await api("/anomalies");
    if (!alerts.length) { el.innerHTML = `<div class="text-emerald-400 text-sm">✓ No active anomaly alerts. All sources nominal.</div>`; return; }
    el.innerHTML = `<table><thead><tr><th>ID</th><th>Source</th><th>Type</th><th>Severity</th><th>Metric</th><th>Detail</th><th>When</th><th></th></tr></thead>
      <tbody>${alerts.map(a => `
        <tr><td class="mono">#${a.id}</td><td>${sourceName(a.source_id)}</td>
        <td>${a.alert_type}</td>
        <td><span class="badge" style="${SEV_BADGE[a.severity] || ''}">${a.severity}</span></td>
        <td>${a.metric_value != null ? a.metric_value.toFixed(2) : "—"}${a.threshold_value != null ? ` / ${a.threshold_value.toFixed(2)}` : ""}</td>
        <td class="text-slate-400">${esc(a.detail || "")}</td>
        <td class="text-slate-500">${fmtTime(a.created_at)}</td>
        <td class="text-right"><button onclick="resolveAlert(${a.id})" class="text-blue-400 hover:text-blue-300 text-xs">resolve</button></td></tr>`).join("")}
      </tbody></table>`;
  } catch (e) { el.innerHTML = `<div class="text-red-400 text-sm">${esc(e.message)}</div>`; }
}

async function resolveAlert(id) {
  try { await api(`/anomalies/${id}/resolve`, { method: "POST" }); toast(`Alert #${id} resolved.`); loadAnomalies(); }
  catch (e) { toast(e.message, "err"); }
}

async function loadEntropy() {
  // show highest average entropy across latest snapshots of all sources
  await loadSourcesData();
  let maxEntropy = 0, maxSrc = null;
  for (const s of SOURCES) {
    try {
      const h = await api(`/backups/${s.id}/history?limit=1`);
      if (h.length && h[0].average_entropy > maxEntropy) { maxEntropy = h[0].average_entropy; maxSrc = s; }
    } catch (_) {}
  }
  const pct = Math.min(100, (maxEntropy / 8) * 100);
  document.getElementById("entropy-marker").style.left = pct + "%";
  const cap = document.getElementById("entropy-caption");
  if (!maxSrc) { cap.textContent = "No snapshot data yet — run a backup to sample entropy."; return; }
  const risk = maxEntropy >= 7.5 ? `<span class="text-red-400 font-semibold">HIGH — possible encryption</span>` : maxEntropy >= 6.5 ? `<span class="text-amber-400">elevated</span>` : `<span class="text-emerald-400">normal</span>`;
  cap.innerHTML = `Peak avg entropy <span class="text-white font-semibold">${maxEntropy.toFixed(3)} bits/byte</span> on <span class="text-white">${esc(maxSrc.name)}</span> — ${risk}`;
}

/* ---------- Policies ---------- */
async function loadPolicies() {
  try { POLICIES = await api("/policies"); } catch (_) { POLICIES = []; }
  const el = document.getElementById("policies-list");
  if (!POLICIES.length) { el.innerHTML = `<div class="text-slate-500 text-sm">No policies yet.</div>`; }
  else {
    el.innerHTML = `<table><thead><tr><th>ID</th><th>Name</th><th>Freq</th><th>Retention</th><th>RPO</th><th>Entropy Thr.</th><th></th></tr></thead>
      <tbody>${POLICIES.map(p => `
        <tr><td class="mono">#${p.id}</td><td class="text-white">${esc(p.name)}</td>
        <td>${p.frequency_minutes}m</td><td>${p.retention_days}d</td><td>${p.rpo_minutes}m</td><td>${p.entropy_threshold}</td>
        <td class="text-right"><button onclick="deletePolicy(${p.id})" class="text-red-400 hover:text-red-300 text-xs">delete</button></td></tr>`).join("")}
      </tbody></table>`;
  }
  const opts = POLICIES.map(p => `<option value="${p.id}">${esc(p.name)} (#${p.id})</option>`).join("") || `<option value="">— no policies —</option>`;
  document.getElementById("attach-policy").innerHTML = opts;
}

async function createPolicy() {
  const name = document.getElementById("pol-name").value.trim();
  const description = document.getElementById("pol-desc").value.trim();
  const policy_yaml = document.getElementById("pol-yaml").value;
  if (!name) return toast("Policy name is required.", "err");
  try {
    await api("/policies", { method: "POST", body: { name, description, policy_yaml } });
    toast("Policy created.");
    document.getElementById("pol-name").value = ""; document.getElementById("pol-desc").value = "";
    loadPolicies();
  } catch (e) { toast(e.message, "err"); }
}

async function deletePolicy(id) {
  if (!confirm("Delete this policy?")) return;
  try { await api(`/policies/${id}`, { method: "DELETE" }); toast("Policy deleted."); loadPolicies(); }
  catch (e) { toast(e.message, "err"); }
}

async function attachPolicy() {
  const pid = parseInt(document.getElementById("attach-policy").value, 10);
  const sid = parseInt(document.getElementById("attach-source").value, 10);
  if (!pid || !sid) return toast("Pick a policy and a source.", "err");
  try { await api(`/policies/${pid}/attach`, { method: "POST", body: { source_id: sid } }); toast("Policy attached."); }
  catch (e) { toast(e.message, "err"); }
}

/* ---------- Compliance ---------- */
async function loadCompliance() {
  const el = document.getElementById("compliance-body");
  el.innerHTML = `<div class="text-slate-500 text-sm">Generating…</div>`;
  try {
    const r = await api("/anomalies/compliance/report");
    const overall = Math.round(r.overall_score);
    const color = overall >= 80 ? "text-emerald-400" : overall >= 55 ? "text-amber-400" : "text-red-400";
    let html = `<div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
      <div class="card p-4"><div class="text-2xl font-bold ${color}">${overall}</div><div class="text-slate-400 text-xs mt-1">Overall Score</div></div>
      <div class="card p-4"><div class="text-2xl font-bold text-white">${r.sources.length}</div><div class="text-slate-400 text-xs mt-1">Sources</div></div>
      <div class="card p-4"><div class="text-2xl font-bold text-amber-400">${r.total_violations}</div><div class="text-slate-400 text-xs mt-1">Violations</div></div>
      <div class="card p-4"><div class="text-2xl font-bold text-red-400">${r.critical_alerts}</div><div class="text-slate-400 text-xs mt-1">Critical Alerts</div></div>
    </div>`;
    if (!r.sources.length) { html += `<div class="text-slate-500 text-sm">No sources to evaluate.</div>`; el.innerHTML = html; return; }
    html += `<div class="card overflow-hidden"><table><thead><tr><th>Source</th><th>Overall</th><th>SOC 2</th><th>HIPAA</th><th>PCI-DSS</th><th>Violations</th></tr></thead>
      <tbody>${r.sources.map(s => {
        const sc = v => `<span class="${v >= 80 ? 'text-emerald-400' : v >= 55 ? 'text-amber-400' : 'text-red-400'}">${v.toFixed(0)}</span>`;
        return `<tr><td class="text-white">${esc(s.source_name)}</td><td>${sc(s.overall_score)}</td>
          <td>${sc(s.soc2_score)}</td><td>${sc(s.hipaa_score)}</td><td>${sc(s.pci_score)}</td>
          <td class="text-slate-400 text-xs">${s.violations.length ? s.violations.map(esc).join("; ") : "—"}</td></tr>`;
      }).join("")}</tbody></table></div>`;
    el.innerHTML = html;
  } catch (e) { el.innerHTML = `<div class="text-red-400 text-sm">${esc(e.message)}</div>`; }
}

/* ---------- boot ---------- */
if (TOKEN) enterApp(); else switchAuth("login");
