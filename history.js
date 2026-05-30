/**
 * Idely — Scan History Page Script
 * Loads all scan_records and scan_logs from storage, renders them with filters and full detail view.
 */

let allRecords = [];
let selectedFilter = "all";
let selectedSeverity = null;
let selectedRecord = null;
let searchQuery = "";

// ── Load data ──────────────────────────────────────────────────────────────────

function loadData() {
  const area = document.getElementById("records-area");
  area.innerHTML = `<div class="loading-spinner"><div class="spinner"></div> Loading scan records…</div>`;

  chrome.runtime.sendMessage({ action: "getScanRecords" }, (res1) => {
    const records = (res1 && res1.records) || [];

    // Also pull scan_logs to enrich any records that came from background reporting
    chrome.runtime.sendMessage({ action: "getScanLogs" }, (res2) => {
      const logs = (res2 && res2.logs) || [];

      // Convert scan_logs into pseudo scan records if they aren't already in records
      const logRecords = logs.map(log => ({
        id: log.id || Math.random().toString(36).slice(2),
        source: log.source || "Unknown",
        url: log.url || "",
        domain: log.domain || "",
        linesScanned: "—",
        findingsCount: 1,
        status: "flagged",
        findings: [{
          type: log.type,
          severity: log.severity,
          category: log.category,
          redacted: log.redacted,
          entropy: log.entropy,
          snippet: log.snippet
        }],
        timestamp: log.timestamp || Date.now(),
        _fromLog: true
      }));

      // Merge, deduplicate by id
      const seenIds = new Set(records.map(r => r.id));
      const merged = [...records];
      logRecords.forEach(lr => {
        // Add log record only if no exact record id match exists
        if (!seenIds.has(lr.id)) {
          merged.push(lr);
        }
      });

      // Sort newest first
      merged.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
      allRecords = merged;

      renderAll();
    });
  });
}

// ── Render all ────────────────────────────────────────────────────────────────

function renderAll() {
  updateCounts();
  renderList();
}

function updateCounts() {
  const total = allRecords.length;
  const flagged = allRecords.filter(r => r.status === "flagged").length;
  const clean = allRecords.filter(r => r.status === "clean").length;
  const empty = allRecords.filter(r => r.status === "empty").length;

  // Critical / High / Medium counts across all flagged findings
  let critical = 0, high = 0, medium = 0;
  allRecords.forEach(r => {
    (r.findings || []).forEach(f => {
      if (f.severity === "CRITICAL") critical++;
      else if (f.severity === "HIGH") high++;
      else if (f.severity === "MEDIUM") medium++;
    });
  });

  setText("count-all", total);
  setText("count-flagged", flagged);
  setText("count-clean", clean);
  setText("count-empty", empty);
  setText("count-critical", critical);
  setText("count-high", high);
  setText("count-medium", medium);
  setText("stat-total", total);
  setText("stat-flagged", flagged);
  setText("stat-clean", clean);
}

function getFilteredRecords() {
  return allRecords.filter(rec => {
    // Status filter
    if (selectedFilter !== "all" && rec.status !== selectedFilter) return false;

    // Severity filter
    if (selectedSeverity) {
      const hasIt = (rec.findings || []).some(f => f.severity === selectedSeverity);
      if (!hasIt) return false;
    }

    // Search
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const inSource = (rec.source || "").toLowerCase().includes(q);
      const inUrl = (rec.url || "").toLowerCase().includes(q);
      const inType = (rec.findings || []).some(f => (f.type || "").toLowerCase().includes(q));
      const inRedacted = (rec.findings || []).some(f => (f.redacted || "").toLowerCase().includes(q));
      if (!inSource && !inUrl && !inType && !inRedacted) return false;
    }

    return true;
  });
}

function renderList() {
  const area = document.getElementById("records-area");
  const filtered = getFilteredRecords();

  if (filtered.length === 0) {
    area.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">🛡️</div>
        <h3>No records found</h3>
        <p>Run the Agent Autopilot scan to populate the history.<br>Records appear here for every source audited.</p>
      </div>`;
    return;
  }

  area.innerHTML = "";
  filtered.forEach(rec => {
    const card = document.createElement("div");
    card.className = `record-card ${rec.status}`;
    card.dataset.id = rec.id;

    const ts = formatTime(rec.timestamp);
    const srcShort = truncate(rec.source || "Unknown", 60);
    const findingsCount = rec.findingsCount || (rec.findings || []).length;

    card.innerHTML = `
      <div class="record-row1">
        <span class="record-status status-${rec.status}">
          ${rec.status === "flagged" ? "⚠ Flagged" : rec.status === "clean" ? "✓ Clean" : "— Empty"}
        </span>
        <span class="record-source" title="${rec.source || ''}">${srcShort}</span>
        <span class="record-time">${ts}</span>
      </div>
      <div class="record-meta">
        <span class="meta-item">📄 ${rec.linesScanned !== undefined ? rec.linesScanned : "—"} lines</span>
        <span class="meta-item">${findingsCount > 0 ? `🔑 ${findingsCount} finding${findingsCount !== 1 ? "s" : ""}` : "🔒 nothing exposed"}</span>
        ${rec.url ? `<span class="meta-item" style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:160px;" title="${rec.url}">🌐 ${getDomain(rec.url)}</span>` : ""}
      </div>
      ${rec.findings && rec.findings.length > 0 ? `
        <div style="margin-top:7px; display:flex; flex-wrap:wrap; gap:4px;">
          ${rec.findings.slice(0,4).map(f => `
            <span style="font-size:9px; padding:2px 7px; border-radius:8px; font-weight:600;
              background:${severityBg(f.severity)}; color:${severityColor(f.severity)};">
              ${f.severity}: ${truncate(f.type, 28)}
            </span>`).join("")}
          ${rec.findings.length > 4 ? `<span style="font-size:9px; color:var(--text-muted);">+${rec.findings.length-4} more</span>` : ""}
        </div>` : ""}
    `;

    card.addEventListener("click", () => selectRecord(rec, card));
    area.appendChild(card);
  });
}

// ── Detail Panel ──────────────────────────────────────────────────────────────

function selectRecord(rec, cardEl) {
  // Deselect previous
  document.querySelectorAll(".record-card.selected").forEach(el => el.classList.remove("selected", "expanded"));
  cardEl.classList.add("selected", "expanded");
  selectedRecord = rec;

  const body = document.getElementById("detail-panel-body");

  const ts = new Date(rec.timestamp).toLocaleString();
  const findingsCount = rec.findingsCount || (rec.findings || []).length;

  body.innerHTML = `
    <div class="detail-field">
      <div class="detail-label">Status</div>
      <div class="detail-value ${rec.status}">${rec.status.toUpperCase()}</div>
    </div>
    <div class="detail-field">
      <div class="detail-label">Source</div>
      <div class="detail-value" style="color:var(--text); font-size:11px;">${rec.source || "Unknown"}</div>
    </div>
    <div class="detail-field">
      <div class="detail-label">Page URL</div>
      <div class="detail-value" style="font-size:10px; color:var(--text-secondary);">${rec.url || "—"}</div>
    </div>
    <div class="detail-field">
      <div class="detail-label">Scanned At</div>
      <div class="detail-value" style="color:var(--text-secondary); font-size:11px;">${ts}</div>
    </div>
    <div class="detail-field">
      <div class="detail-label">Lines Scanned</div>
      <div class="detail-value" style="color:var(--text-secondary);">${rec.linesScanned !== undefined ? rec.linesScanned : "—"}</div>
    </div>
    <div class="detail-field">
      <div class="detail-label">Credentials Found</div>
      <div class="detail-value ${findingsCount > 0 ? "flagged" : ""}">${findingsCount} finding${findingsCount !== 1 ? "s" : ""}</div>
    </div>

    ${findingsCount > 0 ? `
    <div class="detail-label" style="margin-bottom:8px;">Exposed Credentials</div>
    <div class="findings-grid">
      ${(rec.findings || []).map((f, i) => `
        <div class="finding-item">
          <div class="finding-header">
            <span class="finding-type">${f.type || "Unknown"}</span>
            <span class="severity-pill sev-${(f.severity || "").toLowerCase()}">${f.severity || ""}</span>
          </div>
          <div class="finding-redacted">${f.redacted || "—"}</div>
          ${f.snippet ? `<div class="finding-snippet">${escapeHtml(f.snippet)}</div>` : ""}
          <div class="finding-meta-row">
            ${f.category ? `<span>📂 ${f.category}</span>` : ""}
            ${f.entropy ? `<span>〰 entropy: ${f.entropy}</span>` : ""}
          </div>
        </div>`).join("")}
    </div>` : `
    <div style="text-align:center; padding:20px 0; color:var(--text-muted); font-size:12px;">
      <div style="font-size:28px; margin-bottom:8px;">✅</div>
      No credentials were found in this source.
    </div>`}
  `;
}

// ── Filter & Search ───────────────────────────────────────────────────────────

document.querySelectorAll("[data-filter]").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("[data-filter]").forEach(b => b.classList.remove("active"));
    document.querySelectorAll("[data-severity]").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    selectedFilter = btn.dataset.filter;
    selectedSeverity = null;
    renderList();
  });
});

document.querySelectorAll("[data-severity]").forEach(btn => {
  btn.addEventListener("click", () => {
    const already = btn.classList.contains("active");
    document.querySelectorAll("[data-filter]").forEach(b => b.classList.remove("active"));
    document.querySelectorAll("[data-severity]").forEach(b => b.classList.remove("active"));
    if (!already) {
      btn.classList.add("active");
      selectedSeverity = btn.dataset.severity;
      selectedFilter = "all";
    } else {
      selectedSeverity = null;
      document.querySelector("[data-filter='all']").classList.add("active");
    }
    renderList();
  });
});

document.getElementById("search-input").addEventListener("input", (e) => {
  searchQuery = e.target.value.trim();
  renderList();
});

document.getElementById("refresh-btn").addEventListener("click", loadData);

document.getElementById("clear-btn").addEventListener("click", () => {
  if (!confirm("Clear all scan records, logs, and history? This cannot be undone.")) return;
  chrome.runtime.sendMessage({ action: "clearScanRecords" }, () => {
    allRecords = [];
    renderAll();
    document.getElementById("detail-panel-body").innerHTML =
      `<div class="detail-empty"><span style="font-size:32px;">🗑</span><p>Records cleared</p></div>`;
  });
});

// ── Helpers ───────────────────────────────────────────────────────────────────

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.innerText = val;
}

function truncate(str, n) {
  if (!str) return "";
  return str.length > n ? str.substring(0, n) + "…" : str;
}

function getDomain(url) {
  try { return new URL(url).hostname || url; } catch(e) { return url; }
}

function formatTime(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  return d.toLocaleDateString() + " " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function severityColor(sev) {
  if (sev === "CRITICAL") return "#ff1744";
  if (sev === "HIGH") return "#ff5722";
  if (sev === "MEDIUM") return "#ffb300";
  return "#00e676";
}
function severityBg(sev) {
  if (sev === "CRITICAL") return "rgba(255,23,68,0.15)";
  if (sev === "HIGH") return "rgba(255,87,34,0.15)";
  if (sev === "MEDIUM") return "rgba(255,179,0,0.15)";
  return "rgba(0,230,118,0.12)";
}

// ── Boot ──────────────────────────────────────────────────────────────────────
loadData();
