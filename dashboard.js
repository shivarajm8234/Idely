/**
 * Idely — Unified Security Dashboard
 * Merges Scan Audit Trail + Credential Findings + GitHub Scanner + Whitelist + Settings
 */

// ── State ──────────────────────────────────────────────────────────────────────
let allScanRecords = [];
let allCredentials = [];   // from scan_logs (readable) + decrypted scan_history
let decryptedHistoryCache = [];
let selectedCredDomain = "all";


// ── Tab routing ───────────────────────────────────────────────────────────────
const TAB_TITLES = {
  "scan-records": "Audit Trail",
  "credentials": "Credential Findings",
  "github": "GitHub Scanner",
  "whitelist": "Whitelist & Ignores",
  "settings": "Settings"
};

document.querySelectorAll(".nav-item[data-tab]").forEach(btn => {
  btn.addEventListener("click", () => {
    const tab = btn.dataset.tab;
    document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`panel-${tab}`).classList.add("active");
    document.getElementById("tab-title").innerText = TAB_TITLES[tab] || tab;
    if (tab === "scan-records") loadScanRecords();
    else if (tab === "credentials") loadCredentials();
    else if (tab === "whitelist") loadWhitelist();
    else if (tab === "github") loadGitHubHistory();
  });
});

document.getElementById("refresh-btn").addEventListener("click", () => {
  const active = document.querySelector(".nav-item.active");
  if (active) active.click();
});

// ── Clear All ──────────────────────────────────────────────────────────────────
document.getElementById("clear-btn").addEventListener("click", () => {
  if (!confirm("⚠️ Clear ALL scan records, credential logs, and history? This cannot be undone.")) return;
  chrome.storage.local.set({ scan_records: [], scan_logs: [], scan_history: [], github_scan_history: [] }, () => {
    allScanRecords = [];
    allCredentials = [];
    decryptedHistoryCache = [];
    const active = document.querySelector(".nav-item.active");
    if (active) active.click();
  });
});

// ── Export ─────────────────────────────────────────────────────────────────────
document.getElementById("export-json-btn").addEventListener("click", () => {
  const data = { scanRecords: allScanRecords, credentials: decryptedHistoryCache };
  if (allScanRecords.length === 0 && decryptedHistoryCache.length === 0) return alert("No data to export yet.");
  downloadFile(`idely-export-${Date.now()}.json`, "application/json", JSON.stringify(data, null, 2));
});

document.getElementById("export-csv-btn").addEventListener("click", () => {
  if (decryptedHistoryCache.length === 0) return alert("No credential records to export.");
  let csv = "Date,Domain,URL,Type,Severity,Category,Value,Source\n";
  decryptedHistoryCache.forEach(item => {
    const d = new Date(item.timestamp).toISOString();
    csv += `${d},"${esc(item.domain)}","${esc(item.url)}","${esc(item.type)}","${item.severity}","${item.category}","${esc(item.value)}","${esc(item.source)}"\n`;
  });
  downloadFile(`idely-report-${Date.now()}.csv`, "text/csv", csv);
});

function downloadFile(name, mime, content) {
  const a = document.createElement("a");
  a.href = "data:" + mime + ";charset=utf-8," + encodeURIComponent(content);
  a.download = name;
  a.click();
}
function esc(s) { return (s || "").replace(/"/g, '""'); }

// ══════════════════════════════════════════════════════════════════════════════
// TAB 1 — AUDIT TRAIL (scan_records)
// ══════════════════════════════════════════════════════════════════════════════

function loadScanRecords() {
  const list = document.getElementById("sr-list");
  list.innerHTML = `<div class="spinner-wrap"><div class="spinner"></div> Loading records…</div>`;

  chrome.runtime.sendMessage({ action: "getScanRecords" }, (res1) => {
    const records = (res1 && res1.records) || [];

    // Also pull scan_logs to include records stored there
    chrome.runtime.sendMessage({ action: "getScanLogs" }, (res2) => {
      const logs = (res2 && res2.logs) || [];

      const logRecords = logs.map(log => ({
        id: log.id || Math.random().toString(36).slice(2),
        source: log.source || "Unknown",
        url: log.url || "",
        domain: log.domain || "",
        linesScanned: "—",
        findingsCount: 1,
        status: "flagged",
        findings: [{ type: log.type, severity: log.severity, category: log.category, redacted: log.redacted, entropy: log.entropy, snippet: log.snippet }],
        timestamp: log.timestamp || Date.now()
      }));

      const seenIds = new Set(records.map(r => r.id));
      const merged = [...records];
      logRecords.forEach(lr => { if (!seenIds.has(lr.id)) merged.push(lr); });
      merged.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
      allScanRecords = merged;

      updateSrStats();
      renderScanRecords();
    });
  });
}

function updateSrStats() {
  const flagged = allScanRecords.filter(r => r.status === "flagged").length;
  const clean   = allScanRecords.filter(r => r.status === "clean").length;
  const totalFindings = allScanRecords.reduce((n, r) => n + ((r.findings || []).length), 0);
  setText("sr-total",    allScanRecords.length);
  setText("sr-flagged",  flagged);
  setText("sr-clean",    clean);
  setText("sr-findings", totalFindings);
  setText("nb-records",  allScanRecords.length);
}

function getSrFiltered() {
  const q    = (document.getElementById("sr-search").value || "").toLowerCase();
  const stat = document.getElementById("sr-filter").value;
  const sev  = document.getElementById("sr-severity").value;

  return allScanRecords.filter(rec => {
    if (stat !== "all" && rec.status !== stat) return false;
    if (sev !== "all" && !(rec.findings || []).some(f => f.severity === sev)) return false;
    if (q) {
      const inSrc = (rec.source || "").toLowerCase().includes(q);
      const inUrl = (rec.url || "").toLowerCase().includes(q);
      const inType = (rec.findings || []).some(f => (f.type || "").toLowerCase().includes(q));
      if (!inSrc && !inUrl && !inType) return false;
    }
    return true;
  });
}

function renderScanRecords() {
  const list = document.getElementById("sr-list");
  const filtered = getSrFiltered();
  list.innerHTML = "";

  if (filtered.length === 0) {
    list.innerHTML = `<div class="spinner-wrap" style="flex-direction:column; gap:8px;">
      <div style="font-size:32px;">🛡️</div>
      <div>No records found. Run Agent Autopilot to start scanning.</div></div>`;
    return;
  }

  filtered.forEach(rec => {
    const card = document.createElement("div");
    card.className = `record-card ${rec.status}`;
    const ts = fmtTime(rec.timestamp);
    const src = trunc(rec.source || "Unknown", 70);
    const cnt = rec.findingsCount || (rec.findings || []).length;

    card.innerHTML = `
      <div class="rc-row1">
        <span class="rc-status ${rec.status}">
          ${rec.status === "flagged" ? "⚠ Flagged" : rec.status === "clean" ? "✓ Clean" : "— Empty"}
        </span>
        <span class="rc-source" title="${rec.source || ''}">${src}</span>
        <span class="rc-time">${ts}</span>
      </div>
      <div class="rc-meta">
        <span>📄 ${rec.linesScanned !== undefined ? rec.linesScanned : "—"} lines</span>
        <span>${cnt > 0 ? `🔑 ${cnt} finding${cnt !== 1 ? "s" : ""}` : "🔒 nothing exposed"}</span>
        ${rec.url ? `<span title="${rec.url}">🌐 ${getDomain(rec.url)}</span>` : ""}
      </div>
      ${rec.findings && rec.findings.length > 0 ? `
        <div style="margin-top:6px; display:flex; flex-wrap:wrap; gap:3px;">
          ${rec.findings.slice(0,5).map(f => `
            <span class="finding-pill" style="background:${sevBg(f.severity)};color:${sevColor(f.severity)};">
              ${f.severity}: ${trunc(f.type, 24)}
            </span>`).join("")}
          ${rec.findings.length > 5 ? `<span style="font-size:9px;color:var(--text-muted);">+${rec.findings.length-5} more</span>` : ""}
        </div>` : ""}
      <div class="rc-detail">
        <div style="font-family:var(--mono);font-size:10px;color:var(--text-secondary);word-break:break-all;background:rgba(0,0,0,0.2);border-radius:5px;padding:6px 8px;margin-bottom:10px;">
          🌐 ${rec.url || "—"}
        </div>
        ${(rec.findings || []).length > 0 ? (rec.findings.map(f => `
          <div class="finding-box">
            <div class="fb-type">
              <span>${f.type || "Unknown"}</span>
              <span class="sev ${(f.severity||"").toLowerCase()}">${f.severity || ""}</span>
            </div>

            <!-- Location info -->
            <div style="display:flex;flex-wrap:wrap;gap:8px;margin:6px 0;">
              ${f.lineNumber ? `<span style="background:rgba(124,77,255,0.12);color:#a78bfa;padding:2px 8px;border-radius:5px;font-size:10px;font-family:var(--mono);">📍 Line ${f.lineNumber}${f.column ? `, Col ${f.column}` : ""}</span>` : ""}
              ${f.variableName ? `<span style="background:rgba(255,255,255,0.05);color:var(--text-secondary);padding:2px 8px;border-radius:5px;font-size:10px;font-family:var(--mono);">var: <strong style='color:var(--text);'>${escHtml(f.variableName)}</strong></span>` : ""}
              ${f.category ? `<span style="background:rgba(255,255,255,0.04);color:var(--text-muted);padding:2px 8px;border-radius:5px;font-size:10px;">${f.category}</span>` : ""}
              ${f.entropy ? `<span style="background:rgba(255,255,255,0.04);color:var(--text-muted);padding:2px 8px;border-radius:5px;font-size:10px;">entropy: ${f.entropy}</span>` : ""}
            </div>

            <!-- Usage description -->
            ${f.usageDescription ? `<div style="font-size:11px;color:#f6ad55;margin-bottom:6px;">💡 Usage: ${escHtml(f.usageDescription)}</div>` : ""}

            <!-- Redacted value -->
            <div style="font-size:10px;color:var(--text-muted);margin-bottom:3px;">EXPOSED VALUE</div>
            <div class="fb-redacted">${f.redacted || "—"}</div>

            <!-- Exact matched line -->
            ${f.matchedLine ? `
              <div style="font-size:10px;color:var(--text-muted);margin:6px 0 3px;">MATCHED LINE OF CODE</div>
              <div style="font-family:var(--mono);font-size:11px;color:#e2e8f0;background:rgba(0,0,0,0.4);border:1px solid rgba(255,23,68,0.2);border-radius:5px;padding:6px 10px;word-break:break-all;line-height:1.6;">${escHtml(f.matchedLine)}</div>
            ` : ""}

            <!-- Context snippet -->
            ${f.snippet ? `
              <div style="font-size:10px;color:var(--text-muted);margin:6px 0 3px;">SURROUNDING CONTEXT</div>
              <div class="fb-snippet">${escHtml(f.snippet)}</div>
            ` : ""}
          </div>`).join("")) : `<div style="text-align:center;color:var(--text-muted);font-size:12px;padding:14px;">✅ No credentials found in this source.</div>`}
      </div>`;

    card.addEventListener("click", () => {
      const wasExp = card.classList.contains("expanded");
      document.querySelectorAll(".record-card.expanded").forEach(c => c.classList.remove("expanded"));
      if (!wasExp) card.classList.add("expanded");
    });

    list.appendChild(card);
  });
}

// Search/filter live
["sr-search","sr-filter","sr-severity"].forEach(id => {
  document.getElementById(id).addEventListener("input", renderScanRecords);
  document.getElementById(id).addEventListener("change", renderScanRecords);
});

// ══════════════════════════════════════════════════════════════════════════════
// TAB 2 — CREDENTIALS (scan_logs + decrypted scan_history)
// ══════════════════════════════════════════════════════════════════════════════

async function loadCredentials() {
  const tbody = document.getElementById("cred-table-body");
  tbody.innerHTML = `<tr><td colspan="7" class="empty-cell"><div class="spinner-wrap"><div class="spinner"></div> Loading…</div></td></tr>`;

  // 1. Load plaintext scan_logs (fast)
  chrome.runtime.sendMessage({ action: "getScanLogs" }, async (res) => {
    const logs = (res && res.logs) || [];

    // 2. Also decrypt scan_history (encrypted) for full value reveal
    const histData = await new Promise(r => chrome.storage.local.get(["scan_history"], d => r(d)));
    const history = histData.scan_history || [];
    decryptedHistoryCache = [];

    for (const entry of history) {
      try {
        const dec = await IdelyCrypto.decryptObject(entry.encrypted);
        if (dec) decryptedHistoryCache.push({ id: entry.id, domain: entry.domain, url: entry.url, timestamp: entry.timestamp, ...dec });
      } catch(e) {}
    }
    decryptedHistoryCache.sort((a,b) => b.timestamp - a.timestamp);

    // 3. Merge: prefer decryptedHistoryCache (has full value), fill from logs
    const merged = [...decryptedHistoryCache];
    const seenVals = new Set(decryptedHistoryCache.map(x => x.value + "|" + x.source));
    logs.forEach(log => {
      const k = (log.redacted || "") + "|" + (log.source || "");
      if (!seenVals.has(k)) {
        merged.push({ id: log.id, domain: log.domain || getDomain(log.url || ""), url: log.url, timestamp: log.timestamp, type: log.type, severity: log.severity, category: log.category, redacted: log.redacted, value: log.redacted, source: log.source, snippet: log.snippet, entropy: log.entropy });
      }
    });
    merged.sort((a,b) => (b.timestamp||0) - (a.timestamp||0));
    allCredentials = merged;

    setText("nb-creds", allCredentials.length);
    renderCredDomainList();
    renderCredentials();
  });
}

function renderCredDomainList() {
  const list = document.getElementById("cred-domain-list");
  if (!list) return;

  const domains = [...new Set(allCredentials.map(c => c.domain || "Unknown"))].sort();
  
  let html = `<div class="nav-item ${selectedCredDomain === "all" ? "active" : ""}" data-dom="all" style="margin-bottom:2px;">
    <span class="icon">🌍</span> All Websites
    <span class="nav-badge">${allCredentials.length}</span>
  </div>`;

  domains.forEach(d => {
    const count = allCredentials.filter(c => (c.domain || "Unknown") === d).length;
    html += `<div class="nav-item ${selectedCredDomain === d ? "active" : ""}" data-dom="${escAttr(d)}" style="margin-bottom:2px;" title="${escAttr(d)}">
      <span class="icon" style="font-size:12px;">📄</span> <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;">${escHtml(d)}</span>
      <span class="nav-badge">${count}</span>
    </div>`;
  });

  list.innerHTML = html;

  list.querySelectorAll(".nav-item").forEach(item => {
    item.addEventListener("click", () => {
      selectedCredDomain = item.dataset.dom;
      renderCredDomainList();
      renderCredentials();
    });
  });
}

function getCredFiltered() {
  const q   = (document.getElementById("cred-search").value || "").toLowerCase();
  const sev = document.getElementById("cred-severity").value;

  return allCredentials.filter(item => {
    if (selectedCredDomain !== "all" && (item.domain || "Unknown") !== selectedCredDomain) return false;
    if (sev === "CRITICAL" && item.severity !== "CRITICAL") return false;
    if (sev === "HIGH" && !["CRITICAL","HIGH"].includes(item.severity)) return false;
    if (sev === "MEDIUM" && !["CRITICAL","HIGH","MEDIUM"].includes(item.severity)) return false;
    if (q) {
      return (item.domain||"").toLowerCase().includes(q) ||
             (item.type||"").toLowerCase().includes(q) ||
             (item.category||"").toLowerCase().includes(q) ||
             (item.source||"").toLowerCase().includes(q);
    }
    return true;
  });
}

function renderCredentials() {
  const tbody = document.getElementById("cred-table-body");
  const filtered = getCredFiltered();
  tbody.innerHTML = "";

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-cell">No credential records found. Run Agent Autopilot to populate findings.</td></tr>`;
    return;
  }

  filtered.forEach(item => {
    const uid = "v-" + (item.id || Math.random().toString(36).slice(2));
    const ts = new Date(item.timestamp || 0).toLocaleString();
    const redacted = item.redacted || "****";
    const fullVal  = item.value || redacted;

    // Summary row
    const tr = document.createElement("tr");
    tr.style.cursor = "pointer";
    tr.title = "Click to expand full details";
    tr.innerHTML = `
      <td>
        <a href="${item.url || "#"}" target="_blank"
           style="color:var(--text);text-decoration:underline;" title="${escAttr(item.url||"")}"
           onclick="event.stopPropagation()">${escHtml(item.domain || "\u2014")}</a>
      </td>
      <td><strong>${escHtml(item.type || "\u2014")}</strong></td>
      <td><span class="sev ${(item.severity||"").toLowerCase()}">${item.severity || "\u2014"}</span></td>
      <td>
        <span class="secret-val" id="${uid}" data-full="${escAttr(fullVal)}">${redacted}</span>
        <button class="btn btn-ghost btn-mini btn-reveal" data-uid="${uid}"
          style="margin-left:6px;" onclick="event.stopPropagation()">Reveal</button>
      </td>
      <td style="max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
          title="${escAttr(item.source||"")}">${escHtml(trunc(item.source||"\u2014",28))}</td>
      <td style="white-space:nowrap;font-size:11px;">${ts}</td>
      <td>
        <button class="btn btn-danger btn-mini btn-del" data-id="${item.id}"
          onclick="event.stopPropagation()">Remove</button>
      </td>`;
    tbody.appendChild(tr);

    // Expandable full-detail row
    const detailTr = document.createElement("tr");
    detailTr.style.display = "none";
    detailTr.dataset.detail = "1";
    const lineInfo = item.lineNumber
      ? `Line ${item.lineNumber}${item.column ? `, Col ${item.column}` : ""}`
      : null;

    const mkCard = (label, content, extra="") =>
      `<div style="background:rgba(255,255,255,0.03);border:1px solid var(--border);border-radius:7px;padding:10px 12px;${extra}">
        <div style="font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--text-muted);margin-bottom:4px;">${label}</div>
        ${content}
      </div>`;

    const grid = [
      item.source ? mkCard("📄 File / Source",
        `<div style="font-size:11px;font-family:var(--mono);color:var(--text);word-break:break-all;line-height:1.5;">${escHtml(item.source)}</div>`) : "",
      lineInfo ? mkCard("📍 Location",
        `<div style="font-size:16px;font-family:var(--mono);color:#a78bfa;font-weight:800;">${lineInfo}</div>`,
        "background:rgba(124,77,255,0.07);border-color:rgba(124,77,255,0.25);") : "",
      item.variableName ? mkCard("🏷 Variable",
        `<div style="font-size:13px;font-family:var(--mono);color:var(--text);font-weight:600;">${escHtml(item.variableName)}</div>`) : "",
      item.usageDescription ? mkCard("💡 How It's Used",
        `<div style="font-size:12px;color:#f6ad55;line-height:1.5;">${escHtml(item.usageDescription)}</div>`,
        "background:rgba(255,179,0,0.07);border-color:rgba(255,179,0,0.25);") : "",
      item.category ? mkCard("📂 Category",
        `<div style="font-size:12px;color:var(--text-secondary);">${escHtml(item.category)}</div>`) : "",
      item.entropy ? mkCard("\u3030 Entropy",
        `<div style="font-size:16px;font-family:var(--mono);color:var(--text);font-weight:800;">${item.entropy}<span style="font-size:10px;font-weight:400;color:var(--text-muted);margin-left:4px;">bits/char</span></div>`) : "",
      mkCard("🌐 Page URL",
        `<div style="font-size:10px;font-family:var(--mono);color:var(--text-secondary);word-break:break-all;line-height:1.5;">${escHtml(item.url||"\u2014")}</div>`)
    ].filter(Boolean).join("");

    detailTr.innerHTML = `
      <td colspan="7" style="padding:0;background:rgba(0,0,0,0.28);border-top:none;">
        <div style="padding:16px 20px;border-top:2px solid rgba(255,23,68,0.25);">
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;">
            <span style="font-size:14px;font-weight:800;color:var(--red);">🔑 ${escHtml(item.type||"Credential")} \u2014 Full Detail</span>
            <span class="sev ${(item.severity||"").toLowerCase()}">${item.severity||""}</span>
          </div>
          <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:10px;margin-bottom:16px;">${grid}</div>

          <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--text-muted);margin-bottom:6px;">🔒 Exposed Value</div>
          <div style="font-family:var(--mono);font-size:13px;background:rgba(0,0,0,0.4);border:1px solid rgba(255,23,68,0.3);border-radius:7px;padding:10px 14px;color:#ff8099;word-break:break-all;margin-bottom:14px;" id="${uid}-detail">${redacted}</div>

          ${item.matchedLine ? `
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--text-muted);margin-bottom:6px;">📝 Matched Line of Code</div>
            <div style="font-family:var(--mono);font-size:12px;background:rgba(0,0,0,0.45);border:1px solid rgba(255,23,68,0.2);border-radius:7px;padding:10px 14px;color:#e2e8f0;word-break:break-all;line-height:1.8;margin-bottom:14px;">${escHtml(item.matchedLine)}</div>
          ` : ""}

          ${item.snippet ? `
            <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--text-muted);margin-bottom:6px;">🔍 Surrounding Context</div>
            <div style="font-family:var(--mono);font-size:11px;background:rgba(0,0,0,0.25);border:1px solid var(--border);border-radius:7px;padding:10px 14px;color:var(--text-secondary);word-break:break-all;line-height:1.8;">${escHtml(item.snippet)}</div>
          ` : ""}
        </div>
      </td>`;
    tbody.appendChild(detailTr);

    // Toggle expand on row click
    tr.addEventListener("click", () => {
      const isOpen = detailTr.style.display !== "none";
      tbody.querySelectorAll("tr[data-detail='1']").forEach(r => r.style.display = "none");
      tbody.querySelectorAll("tr.row-selected").forEach(r => {
        r.classList.remove("row-selected"); r.style.background = "";
      });
      if (!isOpen) {
        detailTr.style.display = "table-row";
        tr.classList.add("row-selected");
        tr.style.background = "rgba(255,23,68,0.05)";
      }
    });
  });

  // Reveal/hide toggle
  document.querySelectorAll(".btn-reveal").forEach(btn => {
    btn.addEventListener("click", () => {
      const span = document.getElementById(btn.dataset.uid);
      const detailSpan = document.getElementById(btn.dataset.uid + "-detail");
      if (btn.innerText === "Reveal") {
        const full = span.dataset.full;
        span.innerText = full;
        if (detailSpan) detailSpan.innerText = full;
        btn.innerText = "Hide";
      } else {
        const orig = span.dataset.full;
        const r = orig.length > 8 ? orig.substring(0,4)+"..."+orig.substring(orig.length-4) : "****";
        span.innerText = r;
        if (detailSpan) detailSpan.innerText = r;
        btn.innerText = "Reveal";
      }
    });
  });

  // Per-row delete
  document.querySelectorAll(".btn-del").forEach(btn => {
    btn.addEventListener("click", () => {
      if (!confirm("Remove this entry from history?")) return;
      const id = btn.dataset.id;
      chrome.storage.local.get(["scan_history","scan_logs"], res => {
        const h = (res.scan_history||[]).filter(x => x.id !== id);
        const l = (res.scan_logs||[]).filter(x => x.id !== id);
        chrome.storage.local.set({ scan_history: h, scan_logs: l }, loadCredentials);
      });
    });
  });
}



["cred-search","cred-severity"].forEach(id => {
  document.getElementById(id).addEventListener("input", renderCredentials);
  document.getElementById(id).addEventListener("change", renderCredentials);
});

// ══════════════════════════════════════════════════════════════════════════════
// TAB 3 — GITHUB SCANNER
// ══════════════════════════════════════════════════════════════════════════════

document.getElementById("run-github-scan-btn").addEventListener("click", () => {
  const repoUrl = document.getElementById("github-repo-url").value.trim();
  const token   = document.getElementById("github-token").value.trim();
  const branch  = document.getElementById("github-branch").value.trim() || "main";
  const btn     = document.getElementById("run-github-scan-btn");
  const tbody   = document.getElementById("github-results-body");

  if (!repoUrl) return alert("Please enter a GitHub repository URL.");

  btn.disabled = true;
  btn.innerText = "Scanning…";
  tbody.innerHTML = `<tr><td colspan="5" class="empty-cell"><div class="spinner-wrap"><div class="spinner"></div> Fetching commit data…</div></td></tr>`;

  chrome.runtime.sendMessage({ action: "scanGitHubRepo", repoUrl, token, branch }, response => {
    btn.disabled = false;
    btn.innerText = "Begin History Scan";
    if (response && response.success) {
      loadGitHubHistory();
    } else {
      tbody.innerHTML = `<tr><td colspan="5" class="empty-cell" style="color:var(--red);">Error: ${(response && response.error) || "Unknown error"}</td></tr>`;
    }
  });
});

async function loadGitHubHistory() {
  const tbody = document.getElementById("github-results-body");
  chrome.storage.local.get(["github_scan_history"], async res => {
    const history = (res.github_scan_history || []).sort((a,b) => b.timestamp - a.timestamp);
    tbody.innerHTML = "";
    if (history.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" class="empty-cell">No GitHub scans yet.</td></tr>`;
      return;
    }
    for (const entry of history) {
      try {
        const d = await IdelyCrypto.decryptObject(entry.encrypted);
        if (d) {
          const tr = document.createElement("tr");
          tr.innerHTML = `
            <td title="${d.filename}">${trunc(d.filename||"—",40)}</td>
            <td title="${d.commitMessage}">${trunc(d.commitMessage||"—",45)}</td>
            <td>${d.author||"—"}</td>
            <td><strong>${d.type}</strong></td>
            <td><span class="sev ${(d.severity||"").toLowerCase()}">${d.severity}</span></td>`;
          tbody.appendChild(tr);
        }
      } catch(e) {}
    }
  });
}

// ══════════════════════════════════════════════════════════════════════════════
// TAB 4 — WHITELIST
// ══════════════════════════════════════════════════════════════════════════════

function loadWhitelist() {
  chrome.storage.local.get(["whitelist_domains","ignored_secrets"], res => {
    const domains  = res.whitelist_domains  || [];
    const ignored  = res.ignored_secrets    || [];

    const domList = document.getElementById("whitelisted-domains-list");
    domList.innerHTML = domains.length === 0
      ? `<li style="font-size:12px; color:var(--text-muted);">No domains whitelisted.</li>`
      : domains.map(d => `<li class="tag-item"><span>${d}</span><span class="tag-remove" data-domain="${d}">&times;</span></li>`).join("");

    const ignList = document.getElementById("ignored-secrets-list");
    ignList.innerHTML = ignored.length === 0
      ? `<li style="font-size:12px; color:var(--text-muted);">No individual secrets ignored.</li>`
      : ignored.map(v => {
          const r = v.length > 10 ? v.substring(0,5)+"…"+v.substring(v.length-5) : v;
          return `<li style="display:flex; align-items:center; justify-content:space-between; padding:6px 0; border-bottom:1px solid var(--border);">
            <span style="font-family:var(--mono); font-size:12px; color:var(--text-secondary);">${r}</span>
            <button class="btn btn-danger btn-mini btn-rem-ignored" data-val="${escAttr(v)}">Remove</button>
          </li>`;
        }).join("");

    // Domain delete
    document.querySelectorAll(".tag-remove").forEach(el => {
      el.addEventListener("click", () => {
        const d = el.dataset.domain;
        chrome.storage.local.get(["whitelist_domains"], r => {
          chrome.storage.local.set({ whitelist_domains: (r.whitelist_domains||[]).filter(x=>x!==d) }, loadWhitelist);
        });
      });
    });

    // Ignored delete
    document.querySelectorAll(".btn-rem-ignored").forEach(el => {
      el.addEventListener("click", () => {
        const v = el.dataset.val;
        chrome.storage.local.get(["ignored_secrets"], r => {
          chrome.storage.local.set({ ignored_secrets: (r.ignored_secrets||[]).filter(x=>x!==v) }, loadWhitelist);
        });
      });
    });
  });
}

document.getElementById("add-domain-btn").addEventListener("click", () => {
  const input = document.getElementById("new-domain-input");
  const domain = input.value.trim().toLowerCase();
  if (!domain) return;
  chrome.storage.local.get(["whitelist_domains"], res => {
    const current = res.whitelist_domains || [];
    if (!current.includes(domain)) {
      current.push(domain);
      chrome.storage.local.set({ whitelist_domains: current }, () => { input.value = ""; loadWhitelist(); });
    }
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// TAB 5 — SETTINGS
// ══════════════════════════════════════════════════════════════════════════════

chrome.storage.local.get(["developer_mode"], res => {
  document.getElementById("setting-dev-mode").checked = !!res.developer_mode;
});
document.getElementById("setting-dev-mode").addEventListener("change", e => {
  chrome.storage.local.set({ developer_mode: e.target.checked });
});

// ══════════════════════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════════════════════

function setText(id, val) { const el = document.getElementById(id); if (el) el.innerText = val; }
function trunc(s, n) { return !s ? "" : s.length > n ? s.substring(0, n) + "…" : s; }
function getDomain(url) { try { return new URL(url).hostname; } catch(e) { return url || "—"; } }
function fmtTime(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  return d.toLocaleDateString([], {month:"short",day:"numeric"}) + " " + d.toLocaleTimeString([], {hour:"2-digit",minute:"2-digit"});
}
function escHtml(s) { return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }
function escAttr(s) { return String(s||"").replace(/"/g,"&quot;"); }
function sevColor(sev) { return sev==="CRITICAL"?"#ff1744":sev==="HIGH"?"#ff5722":sev==="MEDIUM"?"#ffb300":"#00e676"; }
function sevBg(sev) { return sev==="CRITICAL"?"rgba(255,23,68,0.15)":sev==="HIGH"?"rgba(255,87,34,0.15)":sev==="MEDIUM"?"rgba(255,179,0,0.15)":"rgba(0,230,118,0.12)"; }

// ── Initial load ──────────────────────────────────────────────────────────────
loadScanRecords();
