/**
 * Idely - Background Service Worker (Manifest V3)
 * Orchestrates scanning, stores encrypted logs, manages badge count, and runs GitHub scanning.
 */

// Import scanner and crypto helpers
importScripts("scanner.js", "crypto.js");

// Cache for active findings in current session (unencrypted in memory for active tabs)
const activeTabFindings = {};

// Initialize extension defaults
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(
    ["whitelist_domains", "ignored_secrets", "developer_mode"],
    (res) => {
      const updates = {};
      if (!res.whitelist_domains) updates.whitelist_domains = [];
      if (!res.ignored_secrets) updates.ignored_secrets = [];
      if (res.developer_mode === undefined) updates.developer_mode = false;
      if (Object.keys(updates).length > 0) {
        chrome.storage.local.set(updates);
      }
    }
  );
  console.log("Idely Secret Detector successfully installed.");
});

// Update the badge count and color on a tab
function updateTabBadge(tabId) {
  const findings = activeTabFindings[tabId] || [];
  const count = findings.length;

  if (count === 0) {
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }

  // Set badge text
  chrome.action.setBadgeText({ tabId, text: count.toString() });

  // Set badge color based on highest severity
  let highestSeverity = "LOW";
  for (const f of findings) {
    if (f.severity === "CRITICAL") {
      highestSeverity = "CRITICAL";
      break;
    } else if (f.severity === "HIGH") {
      highestSeverity = "HIGH";
    } else if (f.severity === "MEDIUM" && highestSeverity !== "HIGH") {
      highestSeverity = "MEDIUM";
    }
  }

  let color = "#9e9e9e"; // Low - Grey
  if (highestSeverity === "CRITICAL") color = "#ff1744"; // Critical - Crimson Red
  else if (highestSeverity === "HIGH") color = "#ff5722"; // High - Orange Red
  else if (highestSeverity === "MEDIUM") color = "#ffb300"; // Medium - Amber

  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

// Check if a secret is whitelisted
async function isWhitelisted(domain, value) {
  return new Promise((resolve) => {
    chrome.storage.local.get(["whitelist_domains", "ignored_secrets"], (res) => {
      const domains = res.whitelist_domains || [];
      const ignored = res.ignored_secrets || [];

      // Check if domain is whitelisted
      const domainMatch = domains.some(d => domain.includes(d) || d.includes(domain));
      if (domainMatch) return resolve(true);

      // Check if this specific secret value is ignored
      const secretMatch = ignored.includes(value);
      return resolve(secretMatch);
    });
  });
}

// Save a finding to encrypted history
async function saveFinding(finding, tabUrl, domain) {
  const encryptedPayload = await IdelyCrypto.encryptObject({
    type: finding.type,
    value: finding.value,
    redacted: finding.redacted,
    snippet: finding.snippet,
    severity: finding.severity,
    category: finding.category,
    source: finding.source
  });

  return new Promise((resolve) => {
    chrome.storage.local.get(["scan_history"], (res) => {
      const history = res.scan_history || [];
      const newEntry = {
        id: crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2, 15),
        domain: domain,
        url: tabUrl,
        encrypted: encryptedPayload,
        timestamp: Date.now()
      };
      history.push(newEntry);
      chrome.storage.local.set({ scan_history: history }, () => {
        resolve(newEntry.id);
      });
    });
  });
}

// Save a plaintext readable log entry (for popup display, not sensitive storage)
async function saveScanLog(finding, tabUrl, domain) {
  return new Promise((resolve) => {
    chrome.storage.local.get(["scan_logs"], (res) => {
      const logs = res.scan_logs || [];
      logs.push({
        id: crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2, 15),
        type: finding.type,
        category: finding.category,
        severity: finding.severity,
        redacted: finding.redacted,
        source: finding.source,
        snippet: finding.snippet,
        domain: domain,
        url: tabUrl,
        entropy: finding.entropy,
        timestamp: Date.now()
      });
      // Keep only last 500 entries
      const trimmed = logs.slice(-500);
      chrome.storage.local.set({ scan_logs: trimmed }, resolve);
    });
  });
}

// Send system notification
function showSystemNotification(finding, domain) {
  // Notifications are disabled per user request
  return;
  chrome.notifications.create({
    type: "basic",
    iconUrl: "icons/icon128.png",
    title: `🚨 Exposure Warning! [${finding.severity}]`,
    message: `Exposed ${finding.type} found on ${domain}. Source: ${finding.source}`,
    priority: 2
  });
}

// Save a per-source audit record — always stored, even when no credentials found
async function saveScanRecord(record) {
  return new Promise((resolve) => {
    chrome.storage.local.get(["scan_records"], (res) => {
      const records = res.scan_records || [];
      records.push({
        id: crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2, 15),
        source: record.source || "Unknown",
        url: record.url || "",
        linesScanned: record.linesScanned || 0,
        findingsCount: record.findingsCount || 0,
        status: record.status || "clean",  // "clean" | "flagged" | "empty"
        findings: record.findings || [],
        timestamp: Date.now()
      });
      // Keep last 1000 records
      const trimmed = records.slice(-1000);
      chrome.storage.local.set({ scan_records: trimmed }, resolve);
    });
  });
}

// Listen for messages from content scripts, popups, options
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  // tabId may be null if message comes from autopilot (injected context) – resolve via active tab
  let tabId = sender.tab ? sender.tab.id : null;

  if (request.action === "reportSecrets") {
    const { secrets, url } = request;
    if (!secrets || secrets.length === 0) return sendResponse({ status: "empty" });

    const resolveTabAndProcess = (resolvedTabId) => {
      const domain = url ? (() => { try { return new URL(url).hostname; } catch(e) { return "unknown"; } })() : "unknown";

      (async () => {
        if (!activeTabFindings[resolvedTabId]) {
          activeTabFindings[resolvedTabId] = [];
        }
        const newlyDetected = [];

        for (const secret of secrets) {
          const whitelisted = url ? await isWhitelisted(domain, secret.value) : false;
          if (whitelisted) continue;

          const alreadyInTab = activeTabFindings[resolvedTabId].some(
            s => s.value === secret.value && s.source === secret.source
          );

          if (!alreadyInTab) {
            activeTabFindings[resolvedTabId].push(secret);
            newlyDetected.push(secret);

            // Save encrypted finding to history
            if (url) await saveFinding(secret, url, domain);

            // Also save a plaintext readable log entry for quick display
            await saveScanLog(secret, url || "unknown", domain);
          }
        }

        if (newlyDetected.length > 0) {
          updateTabBadge(resolvedTabId);

          // Send toast alerts to page
          try {
            chrome.tabs.sendMessage(resolvedTabId, {
              action: "showPopupAlert",
              secrets: newlyDetected
            });
          } catch(e) {}

          // System notification
          showSystemNotification(newlyDetected[0], domain);
        }

        sendResponse({ status: "processed", newCount: newlyDetected.length });
      })();
    };

    if (tabId !== null) {
      resolveTabAndProcess(tabId);
    } else {
      // Fallback: query the active tab
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const activeTabId = tabs && tabs.length > 0 ? tabs[0].id : -1;
        resolveTabAndProcess(activeTabId);
      });
    }

    return true; // Keep channel open for async response
  }

  if (request.action === "scanExternalUrls") {
    const { urls, url: tabUrl } = request;
    if (!tabUrl) return sendResponse({ status: "ignored" });
    const domain = new URL(tabUrl).hostname;

    (async () => {
      const allFindings = [];

      for (const targetUrl of urls) {
        try {
          const res = await fetch(targetUrl);
          if (!res.ok) continue;
          const text = await res.text();

          // Scan resource content
          const findings = IdelyScanner.scanText(text, `External Resource: ${targetUrl.split("/").pop()}`);
          allFindings.push(...findings);

          // Check for source mapping URL (source maps often leak full original code!)
          const sourceMapMatch = text.match(/\/\/#\s*sourceMappingURL=(\S+)/);
          if (sourceMapMatch) {
            let sourceMapUrl = sourceMapMatch[1];
            // Resolve relative source map URLs
            if (!sourceMapUrl.startsWith("http")) {
              const base = targetUrl.substring(0, targetUrl.lastIndexOf("/") + 1);
              try {
                sourceMapUrl = new URL(sourceMapUrl, base).href;
              } catch (e) {
                sourceMapUrl = base + sourceMapUrl;
              }
            }

            const smRes = await fetch(sourceMapUrl);
            if (smRes.ok) {
              const smText = await smRes.text();
              const smFindings = IdelyScanner.scanText(smText, `Source Map: ${sourceMapUrl.split("/").pop()}`);
              allFindings.push(...smFindings);
            }
          }
        } catch (e) {
          console.error("[Idely] Failed to fetch external resource:", targetUrl, e);
        }
      }

      if (allFindings.length > 0) {
        const newlyDetected = [];
        if (!activeTabFindings[tabId]) {
          activeTabFindings[tabId] = [];
        }

        for (const secret of allFindings) {
          const whitelisted = await isWhitelisted(domain, secret.value);
          if (whitelisted) continue;

          const alreadyInTab = activeTabFindings[tabId].some(
            s => s.value === secret.value && s.source === secret.source
          );

          if (!alreadyInTab) {
            activeTabFindings[tabId].push(secret);
            newlyDetected.push(secret);
            await saveFinding(secret, tabUrl, domain);
          }
        }

        if (newlyDetected.length > 0) {
          updateTabBadge(tabId);
          chrome.tabs.sendMessage(tabId, {
            action: "showPopupAlert",
            secrets: newlyDetected
          });
          showSystemNotification(newlyDetected[0], domain);
        }
      }
    })();

    sendResponse({ status: "started" });
    return true;
  }

  if (request.action === "getActiveTabFindings") {
    const requestedTabId = request.tabId;
    sendResponse({ findings: activeTabFindings[requestedTabId] || [] });
  }

  if (request.action === "getScanLogs") {
    chrome.storage.local.get(["scan_logs"], (res) => {
      sendResponse({ logs: res.scan_logs || [] });
    });
    return true;
  }

  if (request.action === "clearScanLogs") {
    chrome.storage.local.set({ scan_logs: [], scan_history: [] }, () => {
      sendResponse({ status: "cleared" });
    });
    return true;
  }

  if (request.action === "clearTabFindings") {
    const targetTabId = request.tabId;
    if (activeTabFindings[targetTabId]) {
      activeTabFindings[targetTabId] = [];
      updateTabBadge(targetTabId);
    }
    sendResponse({ status: "cleared" });
  }

  if (request.action === "saveScanRecord") {
    saveScanRecord(request.record).then(() => {
      sendResponse({ status: "saved" });
    });
    return true;
  }

  if (request.action === "getScanRecords") {
    chrome.storage.local.get(["scan_records"], (res) => {
      sendResponse({ records: res.scan_records || [] });
    });
    return true;
  }

  if (request.action === "clearScanRecords") {
    chrome.storage.local.set({ scan_records: [], scan_logs: [], scan_history: [] }, () => {
      sendResponse({ status: "cleared" });
    });
    return true;
  }

  if (request.action === "scanGitHubRepo") {
    const { repoUrl, token, branch } = request;
    runGitHubScan(repoUrl, token, branch)
      .then(result => {
        sendResponse({ success: true, results: result });
      })
      .catch(err => {
        sendResponse({ success: false, error: err.message });
      });
    return true; // async
  }
});

// Clean up cached findings when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  delete activeTabFindings[tabId];
});

// Clean up cached findings when tab URL changes (resets scanner)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading" && tab.url) {
    activeTabFindings[tabId] = [];
    updateTabBadge(tabId);
  }
});

/**
 * GitHub repository scanning engine
 * Fetches commits and scans diffs.
 */
async function runGitHubScan(repoUrl, token, branch = "main") {
  // Parse owner and repo name from URL
  // e.g., https://github.com/owner/repo or github.com/owner/repo
  const cleanedUrl = repoUrl.replace(/https?:\/\/github\.com\//, "").replace(/\.git$/, "");
  const parts = cleanedUrl.split("/");
  if (parts.length < 2) {
    throw new Error("Invalid GitHub Repository URL. Format should be: github.com/owner/repo");
  }
  const owner = parts[0];
  const repo = parts[1];

  const headers = {
    "Accept": "application/vnd.github.v3+json"
  };
  if (token) {
    headers["Authorization"] = `token ${token}`;
  }

  // 1. Fetch commits
  const commitsUrl = `https://api.github.com/repos/${owner}/${repo}/commits?sha=${branch}&per_page=15`;
  const response = await fetch(commitsUrl, { headers });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`GitHub API Error: ${response.status} ${response.statusText}. Details: ${errorText}`);
  }

  const commits = await response.json();
  const scanResults = [];

  // 2. Loop through commits and fetch their specific diffs/files
  for (const commitObj of commits) {
    const sha = commitObj.sha;
    const author = commitObj.commit.author.name;
    const message = commitObj.commit.message;
    const commitDetailUrl = `https://api.github.com/repos/${owner}/${repo}/commits/${sha}`;

    const detailRes = await fetch(commitDetailUrl, { headers });
    if (!detailRes.ok) continue;

    const detailData = await detailRes.json();
    const files = detailData.files || [];

    for (const file of files) {
      const filename = file.filename;
      const patch = file.patch || ""; // Patch contains the git diff additions/deletions

      // Scan only added lines in diffs to minimize noise
      const lines = patch.split("\n");
      let addedContent = "";
      for (const line of lines) {
        if (line.startsWith("+") && !line.startsWith("+++")) {
          addedContent += line.substring(1) + "\n";
        }
      }

      if (!addedContent) continue;

      // Run our scanning module on the diff additions
      const findings = IdelyScanner.scanText(addedContent, `Git Commit ${sha.substring(0, 7)}: ${filename}`);

      for (const finding of findings) {
        // Save GitHub finding securely in local storage
        const encrypted = await IdelyCrypto.encryptObject({
          type: finding.type,
          value: finding.value,
          redacted: finding.redacted,
          snippet: finding.snippet,
          severity: finding.severity,
          category: finding.category,
          source: finding.source,
          commitSha: sha,
          commitMessage: message,
          author: author,
          filename: filename
        });

        const newGitHubFinding = {
          id: crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2, 15),
          repo: `${owner}/${repo}`,
          commit: sha,
          file: filename,
          encrypted: encrypted,
          timestamp: Date.now()
        };

        // Retrieve and append to github scan history
        await new Promise((resolve) => {
          chrome.storage.local.get(["github_scan_history"], (gRes) => {
            const gHistory = gRes.github_scan_history || [];
            gHistory.push(newGitHubFinding);
            chrome.storage.local.set({ github_scan_history: gHistory }, resolve);
          });
        });

        scanResults.push({
          type: finding.type,
          category: finding.category,
          severity: finding.severity,
          redacted: finding.redacted,
          source: `${owner}/${repo} - ${filename}`,
          commitSha: sha,
          commitMessage: message,
          author: author
        });
      }
    }
  }

  return scanResults;
}
