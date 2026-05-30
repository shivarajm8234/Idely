/**
 * Idely - Popup Script
 * Manages active tab findings render and toolbar interactions.
 */

document.addEventListener("DOMContentLoaded", () => {
  const findingsList = document.getElementById("findings-list");
  const findingsCount = document.getElementById("findings-count");
  const severityBadge = document.getElementById("severity-badge");
  const radarPulse = document.querySelector(".radar-pulse");
  const statusText = document.getElementById("status-text");
  const rescanBtn = document.getElementById("rescan-btn");
  const dashboardBtn = document.getElementById("dashboard-btn");
  const historyBtn = document.getElementById("history-btn");
  const autopilotBtn = document.getElementById("autopilot-btn");

  // Query the current active tab
  if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.query) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs.length === 0) {
        setupMockEnvironment();
        return;
      }
      const activeTab = tabs[0];
      const tabId = activeTab.id;
      initExtension(activeTab, tabId);
    });
  } else {
    setupMockEnvironment();
  }

  function initExtension(activeTab, tabId) {
    // Fetch tab findings from background (active cache) + persisted scan_logs
    function loadFindings() {
      chrome.runtime.sendMessage({ action: "getActiveTabFindings", tabId }, (res1) => {
        const activeFindings = (res1 && res1.findings) || [];
        chrome.runtime.sendMessage({ action: "getScanLogs" }, (res2) => {
          const logs = (res2 && res2.logs) || [];
          // Merge active findings + persisted logs (deduplicate by redacted + source)
          const merged = [...activeFindings];
          const seen = new Set(activeFindings.map(f => f.value + "|" + f.source));
          logs.forEach(log => {
            const key = log.redacted + "|" + log.source;
            if (!seen.has(key)) {
              seen.add(key);
              merged.push(log);
            }
          });
          renderFindings(merged);
        });
      });

      // Load full audit trail (all scanned sources including clean ones)
      chrome.runtime.sendMessage({ action: "getScanRecords" }, (res) => {
        const records = (res && res.records) || [];
        renderAuditRecords(records);
      });
    }

    loadFindings();

    // Trigger page reload and show animated agent inspect steps
    rescanBtn.addEventListener("click", () => {
      const terminal = document.getElementById("agent-terminal");
      const logs = document.getElementById("terminal-logs");
      
      // Reveal and clear terminal
      terminal.style.display = "block";
      logs.innerHTML = "";
      rescanBtn.disabled = true;
      statusText.innerText = "Agent scanning code...";

      const logLines = [
        { type: "info", text: "[Idely Agent] Attaching to Chrome tab: " + tabId },
        { type: "info", text: "[Idely Agent] Injecting main-world hooks (inject.js)..." },
        { type: "success", text: "[Idely Agent] Hooked: window.fetch & XMLHttpRequest" },
        { type: "success", text: "[Idely Agent] Hooked: WebSocket protocol frames" },
        { type: "info", text: "[Idely Agent] Initiating DOM MutationObserver checks..." },
        { type: "info", text: "[Idely Agent] Examining storage: LocalStorage & SessionStorage" },
        { type: "info", text: "[Idely Agent] Scanning environment variables (window.*)..." },
        { type: "success", text: "[Idely Agent] Probed 12 potential key variables." },
        { type: "info", text: "[Idely Agent] Auditing external scripts & style sheets..." },
        { type: "success", text: "[Idely Agent] Finished page context scan successfully." }
      ];

      let delay = 0;
      logLines.forEach((line) => {
        setTimeout(() => {
          const div = document.createElement("div");
          div.className = `terminal-line ${line.type}`;
          div.innerText = line.text;
          logs.appendChild(div);
          logs.scrollTop = logs.scrollHeight; // Auto scroll to bottom
        }, delay);
        delay += 250;
      });

      chrome.storage.local.set({ runAutopilotOnTab: true }, () => {
        chrome.runtime.sendMessage({ action: "clearTabFindings", tabId }, () => {
          chrome.tabs.reload(tabId, {}, () => {
            setTimeout(() => {
              loadFindings();
              rescanBtn.disabled = false;
              statusText.innerText = "Monitoring network & scripts...";
              // Auto hide terminal logs 4 seconds after complete
              setTimeout(() => {
                terminal.style.display = "none";
              }, 4000);
            }, delay + 500);
          });
        });
      });
    });

    autopilotBtn.addEventListener("click", () => {
      autopilotBtn.disabled = true;
      statusText.innerText = "Running Autopilot Scan...";
      
      const terminal = document.getElementById("agent-terminal");
      const logs = document.getElementById("terminal-logs");
      terminal.style.display = "block";
      logs.innerHTML = "";
      
      const logLines = [
        { type: "info", text: "[Idely Agent] Attaching Autopilot to active tab..." },
        { type: "info", text: "[Idely Agent] Triggering DOM scan with virtual cursor..." },
        { type: "success", text: "[Idely Agent] Autopilot locked user interaction" },
        { type: "info", text: "[Idely Agent] Executing automated cursor simulation..." }
      ];

      let delay = 0;
      logLines.forEach((line) => {
        setTimeout(() => {
          const div = document.createElement("div");
          div.className = `terminal-line ${line.type}`;
          div.innerText = line.text;
          logs.appendChild(div);
          logs.scrollTop = logs.scrollHeight;
        }, delay);
        delay += 250;
      });

      chrome.tabs.sendMessage(tabId, { action: "startAutopilot" }, (response) => {
        setTimeout(() => {
          loadFindings();
          autopilotBtn.disabled = false;
          statusText.innerText = "Monitoring network & scripts...";
          const div = document.createElement("div");
          div.className = `terminal-line success`;
          div.innerText = "[Idely Agent] Autopilot completed successfully.";
          logs.appendChild(div);
          logs.scrollTop = logs.scrollHeight;
          
          setTimeout(() => {
            terminal.style.display = "none";
          }, 3000);
        }, 8000);
      });
    });
  }

  function setupMockEnvironment() {
    const mockFindings = [
      {
        type: "AWS Access Key ID",
        source: "Inline Scripts (Line 12)",
        snippet: "const aws_key_id = \"AKIAJHETRD6287FUDHSQ\";",
        severity: "CRITICAL"
      },
      {
        type: "Stripe API Key",
        source: "External Resource: main.js",
        snippet: "stripe_secret: \"sk_test_51M3c4eVhGkp8p2...\"",
        severity: "HIGH"
      }
    ];

    renderFindings(mockFindings);

    rescanBtn.addEventListener("click", () => {
      const terminal = document.getElementById("agent-terminal");
      const logs = document.getElementById("terminal-logs");
      
      terminal.style.display = "block";
      logs.innerHTML = "";
      rescanBtn.disabled = true;
      statusText.innerText = "Agent scanning code...";

      const logLines = [
        { type: "info", text: "[Idely Agent] Attaching to Mock tab context..." },
        { type: "info", text: "[Idely Agent] Injecting main-world hooks..." },
        { type: "success", text: "[Idely Agent] Hooked mock environment network APIs" },
        { type: "info", text: "[Idely Agent] Scanning mockup LocalStorage..." },
        { type: "success", text: "[Idely Agent] Found 2 potential credentials!" },
        { type: "info", text: "[Idely Agent] Auditing virtual scripts..." },
        { type: "success", text: "[Idely Agent] Finished virtual context scan." }
      ];

      let delay = 0;
      logLines.forEach((line) => {
        setTimeout(() => {
          const div = document.createElement("div");
          div.className = `terminal-line ${line.type}`;
          div.innerText = line.text;
          logs.appendChild(div);
          logs.scrollTop = logs.scrollHeight;
        }, delay);
        delay += 250;
      });

      setTimeout(() => {
        renderFindings(mockFindings);
        rescanBtn.disabled = false;
        statusText.innerText = "Monitoring network & scripts...";
        setTimeout(() => {
          terminal.style.display = "none";
        }, 4000);
      }, delay + 500);
    });

    autopilotBtn.addEventListener("click", () => {
      const terminal = document.getElementById("agent-terminal");
      const logs = document.getElementById("terminal-logs");
      
      terminal.style.display = "block";
      logs.innerHTML = "";
      autopilotBtn.disabled = true;
      statusText.innerText = "Running Autopilot Scan...";

      const logLines = [
        { type: "info", text: "[Idely Agent] Initiating mockup Autopilot loop..." },
        { type: "info", text: "[Idely Agent] Injecting mock lock overlays..." },
        { type: "success", text: "[Idely Agent] User interaction locked successfully" },
        { type: "info", text: "[Idely Agent] Simulating cursor scan over form coordinates..." },
        { type: "success", text: "[Idely Agent] Mock Autopilot completed." }
      ];

      let delay = 0;
      logLines.forEach((line) => {
        setTimeout(() => {
          const div = document.createElement("div");
          div.className = `terminal-line ${line.type}`;
          div.innerText = line.text;
          logs.appendChild(div);
          logs.scrollTop = logs.scrollHeight;
        }, delay);
        delay += 250;
      });

      setTimeout(() => {
        renderFindings(mockFindings);
        autopilotBtn.disabled = false;
        statusText.innerText = "Monitoring network & scripts...";
        setTimeout(() => {
          terminal.style.display = "none";
        }, 3000);
      }, delay + 500);
    });
  }

  // Render the list of findings into HTML
  function renderFindings(findings) {
    findingsList.innerHTML = "";
    findingsCount.innerText = findings.length.toString();

    if (findings.length === 0) {
      severityBadge.innerText = "Secure";
      severityBadge.className = "badge";
      radarPulse.style.display = "none";
      
      findingsList.innerHTML = `
        <div class="empty-state">
          <div class="shield-icon">🛡️</div>
          <h3>No secrets exposed on this tab</h3>
          <p>Continuous background network, dynamic script, and memory scanning is running.</p>
        </div>
      `;
      return;
    }

    // Determine highest severity
    let highestSeverity = "LOW";
    findings.forEach(f => {
      if (f.severity === "CRITICAL") highestSeverity = "CRITICAL";
      else if (f.severity === "HIGH" && highestSeverity !== "CRITICAL") highestSeverity = "HIGH";
      else if (f.severity === "MEDIUM" && highestSeverity !== "CRITICAL" && highestSeverity !== "HIGH") highestSeverity = "MEDIUM";
    });

    severityBadge.innerText = highestSeverity;
    severityBadge.className = `badge ${highestSeverity.toLowerCase()}`;
    radarPulse.style.display = "block";
    radarPulse.style.backgroundColor = getSeverityColor(highestSeverity);
    radarPulse.style.boxShadow = `0 0 8px ${getSeverityColor(highestSeverity)}`;

    findings.forEach(finding => {
      const card = document.createElement("div");
      card.className = `finding-card ${finding.severity.toLowerCase()}`;

      card.innerHTML = `
        <div class="finding-meta">
          <span class="finding-type" style="color: ${getSeverityColor(finding.severity)}">
            ${finding.type}
          </span>
          <span class="finding-source" title="${finding.source}">
            ${finding.source}
          </span>
        </div>
        <div class="finding-snippet">
          ${finding.snippet}
        </div>
      `;

      findingsList.appendChild(card);
    });
  }

  function getSeverityColor(severity) {
    if (severity === "CRITICAL") return "#ff1744";
    if (severity === "HIGH") return "#ff5722";
    if (severity === "MEDIUM") return "#ffb300";
    return "#00e676";
  }

  // Render full audit trail — every scanned source including clean ones
  function renderAuditRecords(records) {
    let auditSection = document.getElementById("audit-records-section");
    if (!auditSection) {
      // Create section dynamically below findings list
      auditSection = document.createElement("div");
      auditSection.id = "audit-records-section";
      Object.assign(auditSection.style, {
        marginTop: "12px",
        borderTop: "1px solid rgba(255,255,255,0.06)",
        paddingTop: "10px"
      });

      const header = document.createElement("div");
      Object.assign(header.style, {
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        cursor: "pointer",
        padding: "4px 0",
        marginBottom: "6px"
      });
      header.innerHTML = `
        <span style="font-size:11px; font-weight:600; color:#a0aec0; letter-spacing:0.5px; text-transform:uppercase;">
          📋 Audit Records <span id="audit-count-badge" style="background:rgba(124,77,255,0.2); color:#a78bfa; padding:1px 6px; border-radius:10px; font-size:10px;"></span>
        </span>
        <span id="audit-toggle" style="font-size:10px; color:#4a5568;">▼ show</span>
      `;

      const list = document.createElement("div");
      list.id = "audit-records-list";
      list.style.display = "none";

      let expanded = false;
      header.addEventListener("click", () => {
        expanded = !expanded;
        list.style.display = expanded ? "block" : "none";
        document.getElementById("audit-toggle").innerText = expanded ? "▲ hide" : "▼ show";
      });

      auditSection.appendChild(header);
      auditSection.appendChild(list);

      const parent = findingsList ? findingsList.parentElement : document.body;
      if (parent) parent.appendChild(auditSection);
    }

    const list = document.getElementById("audit-records-list");
    const countBadge = document.getElementById("audit-count-badge");
    if (!list) return;

    list.innerHTML = "";
    if (countBadge) countBadge.innerText = records.length;

    if (records.length === 0) {
      list.innerHTML = `<div style="font-size:11px; color:#4a5568; text-align:center; padding:8px;">No scan records yet.</div>`;
      return;
    }

    // Show most recent first
    [...records].reverse().forEach(rec => {
      const row = document.createElement("div");
      Object.assign(row.style, {
        padding: "6px 8px",
        marginBottom: "4px",
        borderRadius: "5px",
        fontSize: "10px",
        lineHeight: "1.5",
        background: rec.status === "flagged" ? "rgba(255,23,68,0.08)" : rec.status === "empty" ? "rgba(255,255,255,0.02)" : "rgba(0,230,118,0.06)",
        borderLeft: `3px solid ${rec.status === "flagged" ? "#ff1744" : rec.status === "empty" ? "#4a5568" : "#00e676"}`
      });

      const ts = new Date(rec.timestamp).toLocaleTimeString();
      const srcShort = (rec.source || "Unknown").substring(0, 45);
      const icon = rec.status === "flagged" ? "⚠️" : rec.status === "empty" ? "—" : "✓";

      row.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <span style="color:${rec.status === "flagged" ? "#ff5555" : rec.status === "empty" ? "#4a5568" : "#50fa7b"}; font-weight:600;">${icon} ${rec.status.toUpperCase()}</span>
          <span style="color:#4a5568;">${ts}</span>
        </div>
        <div style="color:#a0aec0; margin-top:2px;" title="${rec.source}">${srcShort}</div>
        <div style="color:#718096;">Lines: ${rec.linesScanned} &nbsp;|&nbsp; Findings: ${rec.findingsCount}</div>
        ${rec.findings && rec.findings.length > 0 ? rec.findings.map(f =>
          `<div style="color:#ff5555; margin-top:2px;">↳ ${f.type}: <code style="font-size:10px;">${f.redacted}</code></div>`
        ).join("") : ""}
      `;

      list.appendChild(row);
    });
  }

  // Open unified Security Dashboard (merges scan history + options)
  const openDashboard = () => {
    const url = chrome.runtime.getURL("dashboard.html");
    chrome.tabs.create({ url });
  };

  if (dashboardBtn) dashboardBtn.addEventListener("click", openDashboard);
  if (historyBtn)   historyBtn.addEventListener("click",   openDashboard);
});
