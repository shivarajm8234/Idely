/**
 * Idely Secret & Credential Scanning Engine
 * Provides regex rules, entropy metrics, and classification for false positive reduction.
 */

const SECRET_PATTERNS = {
  // ─── Specific High-Confidence Formats ────────────────────────────────────────

  AWS_KEY_ID: {
    name: "AWS Access Key ID",
    regex: /\b(AKIA|ASCA|AOAG|ACCA)[0-9A-Z]{16}\b/g,
    severity: "CRITICAL",
    category: "Cloud Credentials"
  },
  AWS_SECRET_KEY: {
    name: "AWS Secret Access Key",
    regex: /\b[a-zA-Z0-9+/]{40}\b/g,
    entropyThreshold: 4.5,
    severity: "CRITICAL",
    category: "Cloud Credentials",
    contextKeywords: ["aws", "secret", "aws_secret", "access_key", "secret_key"]
  },
  GOOGLE_API_KEY: {
    name: "Google / Firebase API Key",
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    severity: "HIGH",
    category: "Cloud API Keys"
  },
  STRIPE_API_KEY: {
    name: "Stripe API Key",
    regex: /\b[rs]k_(live|test)_[0-9a-zA-Z]{24,100}\b/g,
    severity: "CRITICAL",
    category: "Payment Keys"
  },
  GITHUB_TOKEN: {
    name: "GitHub Token",
    regex: /\bgh[pous]_[0-9a-zA-Z]{36,255}\b/g,
    severity: "CRITICAL",
    category: "Developer Tokens"
  },
  SLACK_WEBHOOK: {
    name: "Slack Webhook URL",
    regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/g,
    severity: "HIGH",
    category: "Webhooks"
  },
  DISCORD_WEBHOOK: {
    name: "Discord Webhook URL",
    regex: /https:\/\/discord\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9\-_]+/g,
    severity: "HIGH",
    category: "Webhooks"
  },
  GENERIC_JWT: {
    name: "JSON Web Token (JWT)",
    regex: /\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b/g,
    severity: "MEDIUM",
    category: "Authentication"
  },
  PRIVATE_KEY: {
    name: "Private Key File Content",
    regex: /-----BEGIN ((RSA|EC|PGP|OPENSSH)? )?PRIVATE KEY-----[\s\S]+?-----END ((RSA|EC|PGP|OPENSSH)? )?PRIVATE KEY-----/g,
    severity: "CRITICAL",
    category: "Credentials"
  },
  DATABASE_CONNECTION: {
    name: "Database Connection String",
    regex: /\b(mongodb(?:\+srv)?|postgres|postgresql|mysql|sqlite|redis|sftp|ftp|ssh):\/\/[a-zA-Z0-9_.\-%]+:[a-zA-Z0-9_.\-%#@^&*()=+~`[\]{}|:;<>?,./]+@[a-zA-Z0-9_.\-%]+(?::[0-9]+)?\b/g,
    severity: "CRITICAL",
    category: "Database"
  },
  SMTP_CREDENTIALS: {
    name: "SMTP Connection Settings",
    regex: /\bsmtp:\/\/[a-zA-Z0-9_.\-%]+:[a-zA-Z0-9_.\-%#@^&*()=+~`[\]{}|:;<>?,./]+@[a-zA-Z0-9_.\-%]+(?::[0-9]+)?\b/g,
    severity: "HIGH",
    category: "Credentials"
  },

  // ─── Generic Credential Assignment Scanner ────────────────────────────────────
  // Catches: apiKey = "...", token: "...", secret = '...', password = "...", etc.

  GENERIC_CREDENTIAL_ASSIGNMENT: {
    name: "Hardcoded Credential Assignment",
    regex: /\b(api[-_]?key|apikey|api[-_]?secret|app[-_]?secret|auth[-_]?token|authtoken|access[-_]?token|accesstoken|secret[-_]?key|secretkey|client[-_]?secret|clientsecret|private[-_]?key|privatekey|password|passwd|pass|db[-_]?pass|db[-_]?password|smtp[-_]?pass|mysql[-_]?pass|bearer[-_]?token|oauth[-_]?token|refresh[-_]?token|id[-_]?token|session[-_]?token|x[-_]?api[-_]?key|AUTHORIZATION|x[-_]?auth[-_]?token|encryption[-_]?key|encryption[-_]?secret|signing[-_]?key|signing[-_]?secret|webhook[-_]?secret|stripe[-_]?key|firebase[-_]?key|twilio[-_]?token|sendgrid[-_]?key|mailgun[-_]?key|sentry[-_]?dsn|algolia[-_]?key|mapbox[-_]?token|cloudinary[-_]?secret|pusher[-_]?key)\s*[:=]\s*['"`]([A-Za-z0-9_\-!@#$%.^&*()+=:/]{8,256})['"`]/gi,
    severity: "HIGH",
    category: "Credentials"
  },

  // ─── Context-Backed Generic Tokens ────────────────────────────────────────────

  OAUTH_CLIENT_SECRET: {
    name: "OAuth Client Secret",
    regex: /\b[a-zA-Z0-9\-_]{24,40}\b/g,
    entropyThreshold: 4.2,
    severity: "HIGH",
    category: "Developer Tokens",
    contextKeywords: ["client_secret", "oauth_secret", "clientsecret", "clientSecret"]
  },
  BEARER_TOKEN: {
    name: "Generic Bearer Token / API Key",
    regex: /\b[a-zA-Z0-9\-_]{20,120}\b/g,
    entropyThreshold: 4.3,
    severity: "MEDIUM",
    category: "Authentication",
    contextKeywords: ["bearer", "api_key", "apikey", "secret_key", "private_key", "auth_token", "authtoken", "access_token", "accesstoken"]
  }
};

/**
 * Calculates Shannon Entropy of a string to estimate randomness.
 */
function calculateEntropy(str) {
  if (!str) return 0;
  const len = str.length;
  const frequencies = {};
  for (let i = 0; i < len; i++) {
    const c = str.charAt(i);
    frequencies[c] = (frequencies[c] || 0) + 1;
  }
  let entropy = 0;
  for (const c in frequencies) {
    const p = frequencies[c] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Check if the string matches general false positive indicators.
 */
function isFalsePositive(matchedStr, keyName) {
  const lower = matchedStr.toLowerCase();

  // Hard skip obviously wrong formats
  if (matchedStr.length < 6) return true;

  // Only skip clearly fake placeholder strings
  const hardPlaceholders = [
    "your_api_key_here", "replace_me", "insert_here", "value_here",
    "example.com", "<your_", "xxx", "yyy", "zzz"
  ];
  if (hardPlaceholders.some(ph => lower.includes(ph))) return true;

  // AWS Secret keys check
  if (keyName === "AWS Secret Access Key") {
    if (/^[A-Za-z]+$/.test(matchedStr) && matchedStr.length < 20) return true;
    if (/^[0-9]+$/.test(matchedStr)) return true;
  }

  return false;
}

/**
 * Scan a text content (JS, DOM, Storage, etc.) for secrets.
 * Returns an array of matched secret objects — each includes file, line, column, usage context.
 */
function scanText(text, sourceName = "Unknown Source") {
  if (!text || typeof text !== "string") return [];
  const results = [];

  // Limit scanning size to prevent browser hang
  if (text.length > 5000000) {
    text = text.substring(0, 5000000);
  }

  // Pre-split lines once for fast line-number lookups
  const lines = text.split("\n");

  /**
   * Given a character index in the full text, return { lineNumber, column, lineText }
   */
  function getLineInfo(charIndex) {
    let pos = 0;
    for (let i = 0; i < lines.length; i++) {
      const lineLen = lines[i].length + 1; // +1 for \n
      if (pos + lineLen > charIndex) {
        return {
          lineNumber: i + 1,
          column: charIndex - pos + 1,
          lineText: lines[i].trim()
        };
      }
      pos += lineLen;
    }
    return { lineNumber: lines.length, column: 0, lineText: "" };
  }

  /**
   * Infer how the credential is used from its surrounding context.
   */
  function inferUsage(snippet, varName, type) {
    const s = snippet.toLowerCase();
    if (/fetch|axios|http|request|post|get|patch|delete/.test(s)) return "Sent in network request";
    if (/header|authorization|bearer|x-api/.test(s)) return "Used as HTTP Authorization header";
    if (/localstorage|sessionstorage/.test(s)) return "Stored in browser storage";
    if (/export|module\.exports/.test(s)) return "Exported as module value";
    if (/process\.env/.test(s)) return "Loaded from process environment";
    if (/window\.|global\./.test(s)) return "Assigned to global scope";
    if (/config|cfg|settings|options/.test(varName.toLowerCase())) return "Embedded in config object";
    if (/init|initialize|setup|create/.test(s)) return "Passed to SDK initializer";
    if (/firebase|aws|stripe|twilio|sendgrid|algolia|cloudinary/.test(s)) return "Used to authenticate cloud service";
    if (/database|db|mongo|postgres|mysql|redis/.test(s)) return "Database credential";
    if (/smtp|mail|email/.test(s)) return "Email/SMTP credential";
    if (/password|passwd|pass/.test(varName.toLowerCase())) return "Hardcoded password";
    if (/token|jwt|auth/.test(varName.toLowerCase())) return "Authentication token";
    if (/key|api/.test(varName.toLowerCase())) return "API key or secret";
    return "Hardcoded credential in source";
  }

  for (const [key, rule] of Object.entries(SECRET_PATTERNS)) {
    rule.regex.lastIndex = 0;
    let match;

    while ((match = rule.regex.exec(text)) !== null) {
      const isGenericAssignment = key === "GENERIC_CREDENTIAL_ASSIGNMENT";
      const matchedValue = isGenericAssignment ? match[2] : match[0];
      const fullMatch = match[0];
      const matchIndex = match.index;

      if (!matchedValue) continue;

      // Extract context around the match
      const startContext = Math.max(0, matchIndex - 80);
      const endContext = Math.min(text.length, matchIndex + fullMatch.length + 80);
      const contextSnippet = text.substring(startContext, endContext);

      // False positive check
      if (isFalsePositive(matchedValue, rule.name)) continue;

      // Context keyword check
      if (rule.contextKeywords) {
        const lowerContext = contextSnippet.toLowerCase();
        const hasKeyword = rule.contextKeywords.some(kw => lowerContext.includes(kw));
        if (!hasKeyword) continue;
      }

      // Entropy check
      if (rule.entropyThreshold) {
        if (calculateEntropy(matchedValue) < rule.entropyThreshold) continue;
      }

      // Deduplicate
      const exists = results.some(r => r.value === matchedValue && r.source === sourceName);
      if (!exists) {
        const redactedValue = matchedValue.length > 8
          ? matchedValue.substring(0, 4) + "..." + matchedValue.substring(matchedValue.length - 4)
          : "****";

        const displaySnippet = isGenericAssignment
          ? fullMatch.replace(matchedValue, `[EXPOSED: ${redactedValue}]`)
          : contextSnippet.replace(matchedValue, `[EXPOSED: ${redactedValue}]`);

        // ── Line-level info ──
        const { lineNumber, column, lineText } = getLineInfo(matchIndex);
        // Extract variable name from generic assignment match[1]
        const varName = isGenericAssignment ? (match[1] || "") : "";
        const usageDescription = inferUsage(contextSnippet, varName, rule.name);

        results.push({
          type: rule.name,
          category: rule.category,
          severity: rule.severity,
          value: matchedValue,
          redacted: redactedValue,
          source: sourceName,
          snippet: displaySnippet.substring(0, 400),
          matchedLine: lineText.substring(0, 200),      // exact line of code
          lineNumber,                                    // 1-based line number
          column,                                        // 1-based column
          variableName: varName || null,                 // e.g. "api_key", "password"
          usageDescription,                             // human-readable usage context
          entropy: calculateEntropy(matchedValue).toFixed(2),
          timestamp: Date.now()
        });
      }
    }
  }

  return results;
}


// Export for Node/ES6/Browser/ServiceWorker global compatibility
const _scannerGlobal = typeof globalThis !== "undefined" ? globalThis
  : typeof self !== "undefined" ? self
  : typeof window !== "undefined" ? window : {};

if (typeof module !== "undefined" && module.exports) {
  module.exports = { scanText, calculateEntropy, SECRET_PATTERNS };
} else {
  _scannerGlobal.IdelyScanner = { scanText, calculateEntropy, SECRET_PATTERNS };
}
