/**
 * Idely - Main World Injected Script
 * Hooks Fetch, XMLHttpRequest, WebSockets and inspects window environment variables.
 * Communicates with content.js (isolated world) via window.postMessage.
 */

(function() {
  // Prevent double injection
  if (window.__idely_injected) return;
  window.__idely_injected = true;

  console.log("[Idely] Main-world scanning hook active.");

  // Helper to safely post findings back to the isolated content script
  function postMessageToContent(type, url, content, source) {
    if (!content || typeof content !== "string" || content.length < 8) return;
    
    // Cap content length to prevent performance issues
    const cappedContent = content.length > 1000000 ? content.substring(0, 1000000) : content;

    window.postMessage({
      sender: "idely-inject-hook",
      type: type,
      url: url || window.location.href,
      content: cappedContent,
      source: source
    }, "*");
  }

  // 1. Hook Fetch API
  const originalFetch = window.fetch;
  window.fetch = async function(resource, config) {
    const response = await originalFetch.apply(this, arguments);
    
    try {
      const url = typeof resource === "string" ? resource : (resource && resource.url ? resource.url : "");
      
      // Hook response data
      const clone = response.clone();
      const text = await clone.text();
      postMessageToContent("IDELY_NETWORK_RESPONSE", url, text, `Fetch API Response (${response.status})`);

      // Hook request config / headers
      if (config) {
        if (config.headers) {
          postMessageToContent("IDELY_NETWORK_REQUEST_HEADERS", url, JSON.stringify(config.headers), "Fetch Request Headers");
        }
        if (config.body && typeof config.body === "string") {
          postMessageToContent("IDELY_NETWORK_REQUEST_BODY", url, config.body, "Fetch Request Body");
        }
      }
    } catch (err) {
      // Fail silently to avoid breaking the page
    }
    
    return response;
  };

  // 2. Hook XMLHttpRequest (XHR)
  const originalOpen = XMLHttpRequest.prototype.open;
  const originalSend = XMLHttpRequest.prototype.send;
  const originalSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;

  XMLHttpRequest.prototype.open = function(method, url, ...args) {
    this._url = url;
    this._method = method;
    this._headers = {};
    return originalOpen.apply(this, [method, url, ...args]);
  };

  XMLHttpRequest.prototype.setRequestHeader = function(header, value) {
    this._headers[header] = value;
    return originalSetRequestHeader.apply(this, [header, value]);
  };

  XMLHttpRequest.prototype.send = function(body) {
    this.addEventListener("load", () => {
      try {
        postMessageToContent(
          "IDELY_NETWORK_RESPONSE", 
          this._url, 
          this.responseText, 
          `XHR Response (${this.status})`
        );
      } catch (e) {}
    });

    if (body && typeof body === "string") {
      postMessageToContent("IDELY_NETWORK_REQUEST_BODY", this._url, body, "XHR Request Body");
    }

    if (Object.keys(this._headers).length > 0) {
      postMessageToContent("IDELY_NETWORK_REQUEST_HEADERS", this._url, JSON.stringify(this._headers), "XHR Request Headers");
    }

    return originalSend.apply(this, [body]);
  };

  // 3. Hook WebSocket Interface
  const OriginalWebSocket = window.WebSocket;
  window.WebSocket = function(url, protocols) {
    const ws = new OriginalWebSocket(url, protocols);
    
    postMessageToContent("IDELY_WEBSOCKET_OPEN", url, url, "WebSocket Connection URL");

    const originalSend = ws.send;
    ws.send = function(data) {
      if (typeof data === "string") {
        postMessageToContent("IDELY_WEBSOCKET_MESSAGE_SENT", url, data, "WebSocket Sent Frame");
      }
      return originalSend.apply(this, [data]);
    };

    ws.addEventListener("message", (event) => {
      if (typeof event.data === "string") {
        postMessageToContent("IDELY_WEBSOCKET_MESSAGE_RECEIVED", url, event.data, "WebSocket Received Frame");
      }
    });

    return ws;
  };
  window.WebSocket.prototype = OriginalWebSocket.prototype;
  // Preserve static fields like CONNECTING, OPEN, etc.
  for (const prop in OriginalWebSocket) {
    if (Object.prototype.hasOwnProperty.call(OriginalWebSocket, prop)) {
      window.WebSocket[prop] = OriginalWebSocket[prop];
    }
  }

  // 4. Scan Global Variables (e.g. process.env, config, settings, API configs)
  function scanGlobals() {
    const keywords = ["env", "config", "api", "key", "secret", "token", "auth", "cred", "firebase", "aws", "stripe", "jwt"];
    const scanned = new Set();

    for (const key in window) {
      if (scanned.has(key)) continue;
      scanned.add(key);

      // Check if variable name contains any of the target keywords
      const isTarget = keywords.some(kw => key.toLowerCase().includes(kw));
      if (isTarget) {
        try {
          const val = window[key];
          if (!val) continue;

          let stringVal = "";
          if (typeof val === "object") {
            // Avoid circular dependencies and keep size small
            stringVal = JSON.stringify(val);
          } else if (typeof val === "function") {
            continue;
          } else {
            stringVal = String(val);
          }

          if (stringVal.length > 8 && stringVal.length < 50000) {
            postMessageToContent(
              "IDELY_GLOBAL_VARIABLE", 
              window.location.href, 
              `${key} = ${stringVal}`, 
              `Global Environment (window.${key})`
            );
          }
        } catch (e) {}
      }
    }
  }

  // Run scans at intervals to catch variables populated by single-page application (SPA) router changes
  setTimeout(scanGlobals, 1000);
  setTimeout(scanGlobals, 3000);
  setTimeout(scanGlobals, 7000);
})();
