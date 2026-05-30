/**
 * Idely - Isolated Content Script
 * Scans DOM mutations, LocalStorage/SessionStorage, injects main-world hooks, and renders premium alert overlays.
 */

// Inject main world script (inject.js) into the actual web page DOM
// inject.js is injected automatically by Chrome via manifest.json "world": "MAIN"

// 1. Scan Storage APIs (LocalStorage & SessionStorage)
function scanStorage() {
  const findings = [];
  
  // Scan LocalStorage
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      const val = localStorage.getItem(key);
      const storageText = `${key}: ${val}`;
      const results = IdelyScanner.scanText(storageText, `LocalStorage [Key: ${key}]`);
      findings.push(...results);
    }
  } catch (e) {}

  // Scan SessionStorage
  try {
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      const val = sessionStorage.getItem(key);
      const storageText = `${key}: ${val}`;
      const results = IdelyScanner.scanText(storageText, `SessionStorage [Key: ${key}]`);
      findings.push(...results);
    }
  } catch (e) {}

  if (findings.length > 0) {
    chrome.runtime.sendMessage({
      action: "reportSecrets",
      secrets: findings,
      url: window.location.href
    });
  }
}

// 2. Scan Document Body DOM Elements (e.g. inline scripts, custom tags, input placeholders)
function scanDOM(rootNode = document) {
  // Extract all inline script contents
  const scripts = rootNode.querySelectorAll("script:not([src])");
  let scriptContent = "";
  scripts.forEach(script => {
    scriptContent += script.textContent + "\n";
  });

  if (scriptContent) {
    const findings = IdelyScanner.scanText(scriptContent, "Inline Scripts");
    if (findings.length > 0) {
      chrome.runtime.sendMessage({
        action: "reportSecrets",
        secrets: findings,
        url: window.location.href
      });
    }
  }

  // Scan text nodes or specific attributes
  const textContent = rootNode.body ? rootNode.body.innerText : "";
  if (textContent.length > 0) {
    const findings = IdelyScanner.scanText(textContent, "Page Content (DOM text)");
    if (findings.length > 0) {
      chrome.runtime.sendMessage({
        action: "reportSecrets",
        secrets: findings,
        url: window.location.href
      });
    }
  }

  // Audits external JS and stylesheet assets loaded in DOM
  const externalAssets = rootNode.querySelectorAll("script[src], link[rel='stylesheet'][href]");
  const urlsToScan = [];
  externalAssets.forEach(asset => {
    try {
      const src = asset.src || asset.href;
      if (src && src.startsWith("http")) {
        urlsToScan.push(src);
      }
    } catch(e){}
  });

  if (urlsToScan.length > 0) {
    chrome.runtime.sendMessage({
      action: "scanExternalUrls",
      urls: urlsToScan,
      url: window.location.href
    });
  }
}

// Initial storage and DOM scan once loaded
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => {
    scanStorage();
    scanDOM();
    setupMutationObserver();
    checkAutopilotTrigger();
  });
} else {
  scanStorage();
  scanDOM();
  setupMutationObserver();
  checkAutopilotTrigger();
}

function checkAutopilotTrigger() {
  try {
    chrome.storage.local.get(["runAutopilotOnTab"], (res) => {
      if (res && res.runAutopilotOnTab) {
        chrome.storage.local.remove("runAutopilotOnTab");
        const autopilotBtn = document.getElementById("start-autopilot");
        if (autopilotBtn) {
          setTimeout(() => {
            autopilotBtn.click();
          }, 1000);
        }
      }
    });
  } catch (e) {}
}

// 3. Monitor Dynamic DOM Changes (Single Page Apps - React/Vue/Angular)
function setupMutationObserver() {
  let debounceTimeout = null;
  const observer = new MutationObserver((mutations) => {
    // Debounce scanning to preserve frame rate and browser performance
    if (debounceTimeout) clearTimeout(debounceTimeout);
    debounceTimeout = setTimeout(() => {
      mutations.forEach((mutation) => {
        if (mutation.addedNodes.length > 0) {
          mutation.addedNodes.forEach((node) => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              scanDOM(node);
            }
          });
        }
      });
    }, 1500); // 1.5s debounce
  });

  if (document.body) {
    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }
}

// 4. Handle incoming window.postMessage updates from main world (inject.js)
window.addEventListener("message", (event) => {
  // Ensure message is from our injected script
  if (event.source !== window || !event.data || event.data.sender !== "idely-inject-hook") {
    return;
  }

  const { type, content, url, source } = event.data;
  if (!content) return;

  const findings = IdelyScanner.scanText(content, source);
  if (findings.length > 0) {
    chrome.runtime.sendMessage({
      action: "reportSecrets",
      secrets: findings,
      url: url
    });
  }
});

// 5. Render custom, modern, premium UI toast alert popup directly inside the webpage DOM
function renderToastAlert(secrets) {
  // If we already have a container, append to it. Else, create one.
  let container = document.getElementById("idely-alert-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "idely-alert-container";
    // Apply styling rules directly
    Object.assign(container.style, {
      position: "fixed",
      bottom: "20px",
      right: "20px",
      zIndex: "2147483647", // Max z-index
      display: "flex",
      flexDirection: "column",
      gap: "10px",
      maxWidth: "380px",
      width: "100%",
      fontFamily: "'Outfit', 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
      pointerEvents: "none"
    });
    document.body.appendChild(container);
  }

  secrets.forEach(secret => {
    const toast = document.createElement("div");
    // Make sure click acts properly on buttons inside toast
    toast.style.pointerEvents = "auto";
    
    // Choose colors depending on severity
    let headerColor = "#ff1744"; // CRITICAL - Crimson
    let shadowColor = "rgba(255, 23, 68, 0.25)";
    if (secret.severity === "HIGH") {
      headerColor = "#ff5722"; // Orange Red
      shadowColor = "rgba(255, 87, 34, 0.25)";
    } else if (secret.severity === "MEDIUM") {
      headerColor = "#ffb300"; // Amber
      shadowColor = "rgba(255, 179, 0, 0.25)";
    } else if (secret.severity === "LOW") {
      headerColor = "#00e676"; // Light Green
      shadowColor = "rgba(0, 230, 118, 0.25)";
    }

    // Modern glassmorphism look
    Object.assign(toast.style, {
      background: "rgba(18, 19, 26, 0.95)",
      backdropFilter: "blur(12px)",
      border: `1px solid rgba(255, 255, 255, 0.08)`,
      borderLeft: `5px solid ${headerColor}`,
      borderRadius: "8px",
      boxShadow: `0 8px 32px 0 ${shadowColor}, 0 2px 8px rgba(0, 0, 0, 0.5)`,
      padding: "16px",
      color: "#e2e8f0",
      transform: "translateX(400px)",
      transition: "transform 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275)",
      position: "relative"
    });

    toast.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 6px;">
        <span style="font-weight: 700; color: ${headerColor}; font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px;">
          ⚠️ ${secret.severity} EXPOSURE
        </span>
        <button class="idely-close-btn" style="background: none; border: none; color: #a0aec0; cursor: pointer; font-size: 16px; padding: 0 4px; line-height: 1;">&times;</button>
      </div>
      <div style="font-size: 14px; font-weight: 600; color: #ffffff; margin-bottom: 8px;">
        ${secret.type}
      </div>
      <div style="font-size: 12px; color: #718096; word-break: break-all; margin-bottom: 6px;">
        <strong>Source:</strong> ${secret.source}
      </div>
      <div style="font-size: 11px; background: rgba(255, 255, 255, 0.04); border: 1px solid rgba(255, 255, 255, 0.06); padding: 8px; border-radius: 4px; font-family: monospace; white-space: pre-wrap; word-break: break-all; color: #e2e8f0; margin-bottom: 8px;">
        ${secret.snippet}
      </div>
      <div style="display: flex; gap: 8px; font-size: 11px; justify-content: flex-end;">
        <button class="idely-ignore-btn" style="background: rgba(255, 255, 255, 0.06); border: 1px solid rgba(255, 255, 255, 0.1); color: #cbd5e0; padding: 4px 8px; border-radius: 4px; cursor: pointer; transition: background 0.2s;">
          Ignore Finding
        </button>
      </div>
    `;

    container.appendChild(toast);

    // Slide in animation
    setTimeout(() => {
      toast.style.transform = "translateX(0)";
    }, 100);

    // Bind event handlers
    const closeBtn = toast.querySelector(".idely-close-btn");
    const ignoreBtn = toast.querySelector(".idely-ignore-btn");

    const removeToast = () => {
      toast.style.transform = "translateX(400px)";
      setTimeout(() => toast.remove(), 400);
    };

    closeBtn.addEventListener("click", removeToast);

    ignoreBtn.addEventListener("click", () => {
      // Send message to background to whitelist this value
      chrome.storage.local.get(["ignored_secrets"], (res) => {
        const ignored = res.ignored_secrets || [];
        if (!ignored.includes(secret.value)) {
          ignored.push(secret.value);
          chrome.storage.local.set({ ignored_secrets: ignored }, () => {
            console.log("[Idely] Secret ignored and whitelisted.");
          });
        }
      });
      removeToast();
    });

    // Auto-remove toast after 10 seconds
    setTimeout(removeToast, 10000);
  });
}

// Receive messages from extension (popup / background)
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "showPopupAlert") {
    renderToastAlert(message.secrets);
  } else if (message.action === "startAutopilot") {
    runAutopilotOnPage();
    if (sendResponse) sendResponse({ success: true });
  }
});

function runAutopilotOnPage() {
  injectLockOverlayAndCursor();
  const overlay = document.getElementById("idely-lock-overlay");
  const cursor = document.getElementById("idely-virtual-cursor");
  const debuggerLogs = document.getElementById("idely-debugger-logs");
  
  if (!overlay || !cursor || !debuggerLogs) return;

  overlay.style.display = "flex";
  cursor.style.display = "block";
  cursor.style.left = "50px";
  cursor.style.top = "50px";
  debuggerLogs.innerHTML = "";

  function logToInspector(text, type = "info") {
    const p = document.createElement("p");
    Object.assign(p.style, {
      margin: "2px 0",
      fontSize: "11px",
      lineHeight: "1.4",
      fontFamily: "monospace"
    });
    if (type === "info") p.style.color = "#8be9fd";
    else if (type === "success") p.style.color = "#50fa7b";
    else if (type === "warn") p.style.color = "#f1fa8c";
    else if (type === "danger") p.style.color = "#ff5555";
    p.innerText = text;
    debuggerLogs.appendChild(p);
    debuggerLogs.scrollTop = debuggerLogs.scrollHeight;
  }

  logToInspector("[Idely Agent] Autopilot sequence initiated.", "info");
  logToInspector("[Idely Agent] Locked UI. Disabling keyboard & mouse.", "warn");

  const scripts = Array.from(document.querySelectorAll("script"));
  logToInspector(`[Idely Agent] Found ${scripts.length} script tags in inspect space.`, "info");

  function moveCursorTo(el, callback, clickAfter = false) {
    if (!el) {
      if (callback) callback();
      return;
    }
    const rect = el.getBoundingClientRect();
    const destX = rect.left + rect.width / 2 + window.scrollX;
    const destY = rect.top + rect.height / 2 + window.scrollY;

    cursor.style.left = destX + "px";
    cursor.style.top = destY + "px";

    setTimeout(() => {
      if (clickAfter) {
        cursor.style.transform = "translate(-50%, -50%) scale(0.6)";
        const ripple = document.createElement("div");
        Object.assign(ripple.style, {
          position: "absolute",
          border: "2px solid #50fa7b",
          borderRadius: "50%",
          pointerEvents: "none",
          left: destX + "px",
          top: destY + "px",
          transform: "translate(-50%, -50%)",
          animation: "idely-ripple 0.6s ease-out",
          zIndex: "2147483647"
        });
        document.body.appendChild(ripple);
        setTimeout(() => {
          ripple.remove();
          cursor.style.transform = "translate(-50%, -50%) scale(1)";
        }, 600);

        el.click();
      }
      if (callback) callback();
    }, 1000);
  }

  function auditScriptContent(scriptNode, name) {
    let code = scriptNode.textContent || "";
    logToInspector(`[Idely Agent] Auditing source: ${name}`, "info");

    if (!code || code.trim().length === 0) {
      logToInspector(`[Idely Agent] Empty or no scannable content.`, "warn");
      // Still record the scan attempt
      chrome.runtime.sendMessage({
        action: "saveScanRecord",
        record: {
          source: name,
          url: window.location.href,
          linesScanned: 0,
          findingsCount: 0,
          status: "empty",
          findings: []
        }
      });
      return;
    }

    const lines = code.split("\n");
    logToInspector(`[Idely Agent] Scanning ${lines.length} lines in: ${name.substring(0, 40)}`, "info");

    // Scan the full code block at once — all patterns including GENERIC_CREDENTIAL_ASSIGNMENT
    const findings = IdelyScanner.scanText(code, name);

    if (findings.length > 0) {
      logToInspector(`   ⚠ Found ${findings.length} credential(s)!`, "danger");
      findings.forEach(f => {
        logToInspector(`   -> [${f.severity}] ${f.type}: ${f.redacted} (entropy: ${f.entropy})`, "danger");
        chrome.runtime.sendMessage({
          action: "reportSecrets",
          secrets: [f],
          url: window.location.href
        });
      });
    } else {
      logToInspector(`   ✓ No credentials detected in this block.`, "success");
    }

    // Always save a record of this scan regardless of result
    chrome.runtime.sendMessage({
      action: "saveScanRecord",
      record: {
        source: name,
        url: window.location.href,
        linesScanned: lines.length,
        findingsCount: findings.length,
        status: findings.length > 0 ? "flagged" : "clean",
        findings: findings.map(f => ({
          type: f.type,
          severity: f.severity,
          category: f.category,
          redacted: f.redacted,
          entropy: f.entropy,
          snippet: f.snippet,
          matchedLine: f.matchedLine || null,
          lineNumber: f.lineNumber || null,
          column: f.column || null,
          variableName: f.variableName || null,
          usageDescription: f.usageDescription || null
        }))
      }
    });
  }

  // Check if sandbox elements are present
  const isSandbox = document.getElementById("panel-inline") || document.getElementById("trigger-fetch");

  let currentScriptIndex = 0;
  function scanGenericScripts() {
    if (currentScriptIndex >= scripts.length) {
      logToInspector("[Idely Agent] Generic code audit completed.", "success");
      setTimeout(completeAutopilotScan, 800);
      return;
    }
    const s = scripts[currentScriptIndex];
    auditScriptContent(s, s.src ? s.src.substring(0, 55) : `Inline Script #${currentScriptIndex+1}`);
    currentScriptIndex++;
    setTimeout(scanGenericScripts, 1000);
  }

  let step = 0;
  function nextStep() {
    step++;
    if (step === 1) {
      const inlinePanel = document.getElementById("panel-inline");
      if (inlinePanel) {
        logToInspector("[Idely Agent] Analyzing Hardcoded Inline Scripts...", "info");
        moveCursorTo(inlinePanel, () => {
          inlinePanel.style.outline = "2px dashed #7c4dff";
          const inlineScripts = Array.from(document.querySelectorAll("script:not([src])"));
          inlineScripts.forEach((s, idx) => auditScriptContent(s, `Inline Script #${idx+1}`));
          setTimeout(() => {
            inlinePanel.style.outline = "";
            nextStep();
          }, 1500);
        });
      } else {
        nextStep();
      }
    } else if (step === 2) {
      const globalsPanel = document.getElementById("panel-globals");
      if (globalsPanel) {
        logToInspector("[Idely Agent] Inspecting window global properties...", "info");
        moveCursorTo(globalsPanel, () => {
          globalsPanel.style.outline = "2px dashed #7c4dff";
          if (window.config) {
            logToInspector("   -> Exposed config object found: window.config", "danger");
            const findings = IdelyScanner.scanText(JSON.stringify(window.config), "Window config object");
            findings.forEach(f => {
              logToInspector(`      * Flagged key: [${f.redacted}]`, "danger");
              chrome.runtime.sendMessage({
                action: "reportSecrets",
                secrets: [f],
                url: window.location.href
              });
            });
          }
          setTimeout(() => {
            globalsPanel.style.outline = "";
            nextStep();
          }, 1500);
        });
      } else {
        nextStep();
      }
    } else if (step === 3) {
      const fetchBtn = document.getElementById("trigger-fetch");
      if (fetchBtn) {
        logToInspector("[Idely Agent] Intercepting Dynamic Fetch Call...", "info");
        moveCursorTo(fetchBtn, () => {
          logToInspector("   -> Triggered fetch endpoint: POST /echo-endpoint", "success");
          nextStep();
        }, true);
      } else {
        nextStep();
      }
    } else if (step === 4) {
      const xhrBtn = document.getElementById("trigger-xhr");
      if (xhrBtn) {
        logToInspector("[Idely Agent] Intercepting XMLHttpRequest hook...", "info");
        moveCursorTo(xhrBtn, () => {
          logToInspector("   -> Triggered XHR endpoint: POST /xhr-mock-endpoint", "success");
          nextStep();
        }, true);
      } else {
        nextStep();
      }
    } else if (step === 5) {
      const storageBtn = document.getElementById("populate-storage") || document.getElementById("populate-storage");
      if (storageBtn) {
        logToInspector("[Idely Agent] Intercepting Storage writes...", "info");
        moveCursorTo(storageBtn, () => {
          logToInspector("   -> LocalStorage updated with key 'IDELY_MOCK_GITHUB_TOKEN'", "success");
          scanStorage();
          nextStep();
        }, true);
      } else {
        nextStep();
      }
    } else {
      logToInspector("[Idely Agent] Autopilot inspection completed.", "success");
      setTimeout(completeAutopilotScan, 800);
    }
  }

  function completeAutopilotScan() {
    cursor.style.display = "none";
    const statusText = document.getElementById("idely-autopilot-status");
    if (statusText) {
      statusText.innerText = "AUDIT COMPLETE";
      statusText.style.color = "#50fa7b";
      statusText.style.animation = "none";
    }

    const actions = document.getElementById("idely-autopilot-actions");
    if (actions) {
      actions.style.display = "flex";
      const closeBtn = document.getElementById("idely-close-autopilot-btn");
      if (closeBtn) {
        closeBtn.onclick = () => {
          overlay.style.display = "none";
        };
      }
    }
  }

  if (!isSandbox) {
    setTimeout(scanGenericScripts, 500);
  } else {
    setTimeout(nextStep, 500);
  }
}

function injectLockOverlayAndCursor() {
  if (!document.getElementById("idely-lock-overlay")) {
    const overlay = document.createElement("div");
    overlay.id = "idely-lock-overlay";
    Object.assign(overlay.style, {
      position: "fixed",
      top: "0",
      left: "0",
      width: "100vw",
      height: "100vh",
      background: "rgba(10, 11, 15, 0.85)",
      backdropFilter: "blur(5px)",
      zIndex: "2147483646",
      display: "none",
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center",
      color: "#ffffff",
      fontFamily: "'Outfit', 'Inter', monospace",
      padding: "20px"
    });
    
    const banner = document.createElement("div");
    Object.assign(banner.style, {
      background: "#16171e",
      border: "1px solid rgba(124, 77, 255, 0.4)",
      padding: "20px 30px",
      borderRadius: "10px",
      boxShadow: "0 10px 40px rgba(0,0,0,0.8)",
      textAlign: "center",
      maxWidth: "500px",
      width: "100%"
    });
    
    banner.innerHTML = `
      <h2 style="margin:0; font-size: 18px; color:#ffffff; font-weight:700; letter-spacing:0.5px;">Idely Agent Autopilot Active</h2>
      <p style="margin: 6px 0 0 0; color: #a0aec0; font-size:11px;">Auditing page context and resource lines.</p>
      <div id="idely-autopilot-status" style="animation: idely-pulse 1.5s infinite alternate; font-size: 12px; font-weight: 700; color: #7c4dff; letter-spacing: 1px; margin-top: 8px;">DO NOT INTERFERE — CONTROLLING CURSOR</div>
      
      <!-- Debugger logs console container -->
      <div id="idely-debugger-logs" style="background:#090a0f; border: 1px solid rgba(255,255,255,0.05); border-radius: 6px; height: 180px; margin-top: 15px; padding: 10px; overflow-y: auto; text-align: left; font-family: monospace; display: flex; flex-direction: column; gap: 4px;">
      </div>

      <!-- Action buttons after execution finishes -->
      <div id="idely-autopilot-actions" style="margin-top: 15px; display: none; justify-content: center;">
        <button id="idely-close-autopilot-btn" style="background: linear-gradient(135deg, #7c4dff 0%, #ff1744 100%); border: none; color: #ffffff; font-family: sans-serif; font-size: 12px; font-weight: 600; padding: 8px 18px; border-radius: 6px; cursor: pointer; box-shadow: 0 4px 12px rgba(124, 77, 255, 0.3);">
          Close Audit Report
        </button>
      </div>
    `;
    
    const styleTag = document.createElement("style");
    styleTag.textContent = `
      @keyframes idely-pulse {
        0% { opacity: 0.5; text-shadow: 0 0 5px rgba(124,77,255,0.5); }
        100% { opacity: 1; text-shadow: 0 0 15px rgba(124,77,255,1); }
      }
      @keyframes idely-ripple {
        0% { width: 0; height: 0; opacity: 1; }
        100% { width: 80px; height: 80px; opacity: 0; }
      }
    `;
    document.head.appendChild(styleTag);
    
    overlay.appendChild(banner);
    document.body.appendChild(overlay);
  }

  if (!document.getElementById("idely-virtual-cursor")) {
    const cursor = document.createElement("div");
    cursor.id = "idely-virtual-cursor";
    Object.assign(cursor.style, {
      position: "absolute",
      width: "24px",
      height: "24px",
      background: "radial-gradient(circle, rgba(124, 77, 255, 1) 0%, rgba(124, 77, 255, 0.4) 60%, transparent 100%)",
      border: "2px solid #ffffff",
      borderRadius: "50%",
      pointerEvents: "none",
      zIndex: "2147483647",
      transition: "all 0.8s cubic-bezier(0.25, 0.8, 0.25, 1)",
      boxShadow: "0 0 15px #7c4dff, inset 0 0 8px #7c4dff",
      transform: "translate(-50%, -50%)",
      display: "none"
    });
    document.body.appendChild(cursor);
  }
}
