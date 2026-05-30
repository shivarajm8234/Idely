/**
 * Idely - Options & Dashboard Controller
 * Handles storage decryption, reports export, whitelist domains, and GitHub repository audits.
 */

document.addEventListener("DOMContentLoaded", async () => {
  // Tab Switching
  const navItems = document.querySelectorAll(".nav-item");
  const tabPanels = document.querySelectorAll(".tab-panel");
  const tabTitle = document.getElementById("tab-title");

  navItems.forEach(item => {
    item.addEventListener("click", () => {
      const targetTab = item.getAttribute("data-tab");

      navItems.forEach(nav => nav.classList.remove("active"));
      tabPanels.forEach(panel => panel.classList.remove("active"));

      item.classList.add("active");
      document.getElementById(`panel-${targetTab}`).classList.add("active");
      
      // Update Title
      tabTitle.innerText = item.textContent.trim().replace(/^[^\s]+\s+/, "");

      if (targetTab === "history") {
        loadHistory();
      } else if (targetTab === "whitelist") {
        loadWhitelist();
      } else if (targetTab === "github") {
        loadGitHubHistory();
      }
    });
  });

  // Global variables to cache decrypted history for searching and exporting
  let decryptedHistoryCache = [];

  // --- TAB 1: SCAN HISTORY LOGS ---
  const historyTableBody = document.getElementById("history-table-body");
  const searchHistory = document.getElementById("search-history");
  const filterSeverity = document.getElementById("filter-severity");

  async function loadHistory() {
    chrome.storage.local.get(["scan_history"], async (res) => {
      const history = res.scan_history || [];
      decryptedHistoryCache = [];

      historyTableBody.innerHTML = `<tr><td colspan="7" class="empty-table-cell">Decrypting logs securely...</td></tr>`;

      for (const entry of history) {
        try {
          const decrypted = await IdelyCrypto.decryptObject(entry.encrypted);
          if (decrypted) {
            decryptedHistoryCache.push({
              id: entry.id,
              domain: entry.domain,
              url: entry.url,
              timestamp: entry.timestamp,
              ...decrypted
            });
          }
        } catch (err) {
          console.error("Failed to decrypt history item:", err);
        }
      }

      // Sort by newest first
      decryptedHistoryCache.sort((a, b) => b.timestamp - a.timestamp);
      renderFilteredHistory();
    });
  }

  function renderFilteredHistory() {
    const searchVal = searchHistory.value.toLowerCase();
    const severityVal = filterSeverity.value;

    const filtered = decryptedHistoryCache.filter(item => {
      const matchesSearch = 
        item.domain.toLowerCase().includes(searchVal) ||
        item.url.toLowerCase().includes(searchVal) ||
        item.type.toLowerCase().includes(searchVal) ||
        item.category.toLowerCase().includes(searchVal);

      let matchesSeverity = true;
      if (severityVal === "CRITICAL") {
        matchesSeverity = item.severity === "CRITICAL";
      } else if (severityVal === "HIGH") {
        matchesSeverity = ["CRITICAL", "HIGH"].includes(item.severity);
      } else if (severityVal === "MEDIUM") {
        matchesSeverity = ["CRITICAL", "HIGH", "MEDIUM"].includes(item.severity);
      }

      return matchesSearch && matchesSeverity;
    });

    historyTableBody.innerHTML = "";

    if (filtered.length === 0) {
      historyTableBody.innerHTML = `<tr><td colspan="7" class="empty-table-cell">No scan records found matching filters.</td></tr>`;
      return;
    }

    filtered.forEach(item => {
      const tr = document.createElement("tr");
      
      const timeStr = new Date(item.timestamp).toLocaleString();
      const redactedDisplay = item.redacted || "****";

      tr.innerHTML = `
        <td>
          <a href="${item.url}" target="_blank" style="color: #cbd5e0; text-decoration: underline;" title="${item.url}">
            ${item.domain}
          </a>
        </td>
        <td><strong>${item.type}</strong></td>
        <td><span class="badge-sec ${item.severity.toLowerCase()}">${item.severity}</span></td>
        <td>
          <span class="secret-value" data-id="${item.id}" data-full="${item.value}" style="font-family: monospace; background: rgba(255,255,255,0.05); padding: 4px 6px; border-radius: 4px;">
            ${redactedDisplay}
          </span>
          <button class="btn-reveal" data-id="${item.id}" style="background: none; border: none; cursor: pointer; font-size: 11px; margin-left: 6px; color: #7c4dff;">Reveal</button>
        </td>
        <td style="max-width: 150px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${item.source}">${item.source}</td>
        <td>${timeStr}</td>
        <td>
          <button class="btn-delete btn-danger" data-id="${item.id}" style="padding: 4px 8px; font-size: 10px;">Remove</button>
        </td>
      `;

      historyTableBody.appendChild(tr);
    });

    // Bind event listeners to reveal buttons
    document.querySelectorAll(".btn-reveal").forEach(btn => {
      btn.addEventListener("click", (e) => {
        const id = e.target.getAttribute("data-id");
        const span = document.querySelector(`.secret-value[data-id="${id}"]`);
        if (e.target.innerText === "Reveal") {
          span.innerText = span.getAttribute("data-full");
          e.target.innerText = "Hide";
        } else {
          const item = decryptedHistoryCache.find(x => x.id === id);
          span.innerText = item.redacted || "****";
          e.target.innerText = "Reveal";
        }
      });
    });

    // Bind event listeners to individual delete buttons
    document.querySelectorAll(".btn-delete").forEach(btn => {
      btn.addEventListener("click", (e) => {
        const id = e.target.getAttribute("data-id");
        deleteHistoryItem(id);
      });
    });
  }

  function deleteHistoryItem(id) {
    if (!confirm("Are you sure you want to delete this scan entry?")) return;

    chrome.storage.local.get(["scan_history"], (res) => {
      const history = res.scan_history || [];
      const updated = history.filter(x => x.id !== id);
      chrome.storage.local.set({ scan_history: updated }, () => {
        loadHistory();
      });
    });
  }

  // Clear all history logs
  document.getElementById("clear-all-history-btn").addEventListener("click", () => {
    if (!confirm("⚠️ WARNING: This will permanently wipe all encrypted history records. Continue?")) return;
    chrome.storage.local.set({ scan_history: [] }, () => {
      loadHistory();
    });
  });

  searchHistory.addEventListener("input", renderFilteredHistory);
  filterSeverity.addEventListener("change", renderFilteredHistory);

  // --- EXPORT REPORTS ---
  document.getElementById("export-json-btn").addEventListener("click", () => {
    if (decryptedHistoryCache.length === 0) return alert("No records available to export.");
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(decryptedHistoryCache, null, 2));
    const dlAnchorElem = document.createElement('a');
    dlAnchorElem.setAttribute("href", dataStr);
    dlAnchorElem.setAttribute("download", `idely-scan-report-${Date.now()}.json`);
    dlAnchorElem.click();
  });

  document.getElementById("export-csv-btn").addEventListener("click", () => {
    if (decryptedHistoryCache.length === 0) return alert("No records available to export.");
    
    // Construct CSV Header
    let csvContent = "Date,Domain,URL,Type,Severity,Category,Value,Source\n";
    
    decryptedHistoryCache.forEach(item => {
      const date = new Date(item.timestamp).toISOString();
      // Sanitize fields to escape quotes and commas
      const domain = `"${item.domain.replace(/"/g, '""')}"`;
      const url = `"${item.url.replace(/"/g, '""')}"`;
      const type = `"${item.type.replace(/"/g, '""')}"`;
      const severity = `"${item.severity}"`;
      const category = `"${item.category}"`;
      const value = `"${item.value.replace(/"/g, '""')}"`;
      const source = `"${item.source.replace(/"/g, '""')}"`;

      csvContent += `${date},${domain},${url},${type},${severity},${category},${value},${source}\n`;
    });

    const dataStr = "data:text/csv;charset=utf-8," + encodeURIComponent(csvContent);
    const dlAnchorElem = document.createElement('a');
    dlAnchorElem.setAttribute("href", dataStr);
    dlAnchorElem.setAttribute("download", `idely-scan-report-${Date.now()}.csv`);
    dlAnchorElem.click();
  });


  // --- TAB 2: WHITELIST MANAGEMENT ---
  const newDomainInput = document.getElementById("new-domain-input");
  const addDomainBtn = document.getElementById("add-domain-btn");
  const whitelistedDomainsList = document.getElementById("whitelisted-domains-list");
  const ignoredSecretsList = document.getElementById("ignored-secrets-list");

  function loadWhitelist() {
    chrome.storage.local.get(["whitelist_domains", "ignored_secrets"], (res) => {
      const domains = res.whitelist_domains || [];
      const ignored = res.ignored_secrets || [];

      // Render domains tags
      whitelistedDomainsList.innerHTML = "";
      if (domains.length === 0) {
        whitelistedDomainsList.innerHTML = `<li style="font-size: 12px; color: var(--text-secondary);">No domains whitelisted.</li>`;
      } else {
        domains.forEach(domain => {
          const li = document.createElement("li");
          li.className = "tag-item";
          li.innerHTML = `
            <span>${domain}</span>
            <span class="tag-remove" data-domain="${domain}">&times;</span>
          `;
          whitelistedDomainsList.appendChild(li);
        });
      }

      // Render ignored signatures
      ignoredSecretsList.innerHTML = "";
      if (ignored.length === 0) {
        ignoredSecretsList.innerHTML = `<li style="font-size: 12px; color: var(--text-secondary);">No individual secrets ignored.</li>`;
      } else {
        ignored.forEach(val => {
          const li = document.createElement("li");
          li.className = "ignored-item";
          
          // Display short/redacted version
          const redacted = val.length > 10 ? val.substring(0, 5) + "..." + val.substring(val.length - 5) : val;

          li.innerHTML = `
            <span style="font-family: monospace;">Secret: ${redacted}</span>
            <button class="btn-remove-ignored btn-danger" data-val="${val}" style="padding: 2px 6px; font-size: 10px;">Remove</button>
          `;
          ignoredSecretsList.appendChild(li);
        });
      }

      // Add Whitelist Domain Action
      addDomainBtn.onclick = () => {
        const domain = newDomainInput.value.trim().toLowerCase();
        if (!domain) return;

        chrome.storage.local.get(["whitelist_domains"], (res) => {
          const current = res.whitelist_domains || [];
          if (!current.includes(domain)) {
            current.push(domain);
            chrome.storage.local.set({ whitelist_domains: current }, () => {
              newDomainInput.value = "";
              loadWhitelist();
            });
          }
        });
      };

      // Bind deletes
      document.querySelectorAll(".tag-remove").forEach(btn => {
        btn.onclick = (e) => {
          const domain = e.target.getAttribute("data-domain");
          chrome.storage.local.get(["whitelist_domains"], (res) => {
            const current = res.whitelist_domains || [];
            const updated = current.filter(d => d !== domain);
            chrome.storage.local.set({ whitelist_domains: updated }, loadWhitelist);
          });
        };
      });

      document.querySelectorAll(".btn-remove-ignored").forEach(btn => {
        btn.onclick = (e) => {
          const val = e.target.getAttribute("data-val");
          chrome.storage.local.get(["ignored_secrets"], (res) => {
            const current = res.ignored_secrets || [];
            const updated = current.filter(x => x !== val);
            chrome.storage.local.set({ ignored_secrets: updated }, loadWhitelist);
          });
        };
      });
    });
  }


  // --- TAB 3: GITHUB REPOSITORY SCANNER ---
  const githubRepoUrl = document.getElementById("github-repo-url");
  const githubToken = document.getElementById("github-token");
  const githubBranch = document.getElementById("github-branch");
  const runGithubScanBtn = document.getElementById("run-github-scan-btn");
  const githubResultsBody = document.getElementById("github-results-body");

  runGithubScanBtn.addEventListener("click", () => {
    const repoUrl = githubRepoUrl.value.trim();
    const token = githubToken.value.trim();
    const branch = githubBranch.value.trim() || "main";

    if (!repoUrl) {
      alert("Please enter a valid GitHub repository URL.");
      return;
    }

    runGithubScanBtn.disabled = true;
    runGithubScanBtn.innerText = "Scanning Repository (Fetching Logs)...";
    githubResultsBody.innerHTML = `<tr><td colspan="5" class="empty-table-cell">Fetching commit data from GitHub. Please wait, this audits commits locally...</td></tr>`;

    chrome.runtime.sendMessage({
      action: "scanGitHubRepo",
      repoUrl,
      token,
      branch
    }, (response) => {
      runGithubScanBtn.disabled = false;
      runGithubScanBtn.innerText = "Begin History Scan";

      if (response && response.success) {
        loadGitHubHistory();
      } else {
        const errMsg = (response && response.error) || "Unknown scan error occurred.";
        githubResultsBody.innerHTML = `<tr><td colspan="5" class="empty-table-cell" style="color: #ff1744;">Error: ${errMsg}</td></tr>`;
      }
    });
  });

  async function loadGitHubHistory() {
    chrome.storage.local.get(["github_scan_history"], async (res) => {
      const history = res.github_scan_history || [];
      githubResultsBody.innerHTML = "";

      if (history.length === 0) {
        githubResultsBody.innerHTML = `<tr><td colspan="5" class="empty-table-cell">No repository scans conducted yet. Run a scan above to audit logs.</td></tr>`;
        return;
      }

      // Sort by newest scan first
      history.sort((a, b) => b.timestamp - a.timestamp);

      for (const entry of history) {
        try {
          const decrypted = await IdelyCrypto.decryptObject(entry.encrypted);
          if (decrypted) {
            const tr = document.createElement("tr");
            tr.innerHTML = `
              <td>${decrypted.filename}</td>
              <td title="${decrypted.commitMessage}">${decrypted.commitMessage}</td>
              <td>${decrypted.author}</td>
              <td><strong>${decrypted.type}</strong></td>
              <td><span class="badge-sec ${decrypted.severity.toLowerCase()}">${decrypted.severity}</span></td>
            `;
            githubResultsBody.appendChild(tr);
          }
        } catch (err) {
          console.error("Failed to decrypt GitHub record:", err);
        }
      }
    });
  }


  // --- TAB 4: CONFIGURATION SETTINGS ---
  const settingDevMode = document.getElementById("setting-dev-mode");

  // Load configuration
  chrome.storage.local.get(["developer_mode"], (res) => {
    settingDevMode.checked = !!res.developer_mode;
  });

  // Save changes
  settingDevMode.addEventListener("change", () => {
    chrome.storage.local.set({ developer_mode: settingDevMode.checked }, () => {
      console.log(`[Idely] Developer Mode toggled to: ${settingDevMode.checked}`);
    });
  });

  // Initial load
  loadHistory();
});
