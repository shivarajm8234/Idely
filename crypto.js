/**
 * Idely Crypto Helper
 * Encrypts and decrypts sensitive data in local storage using WebCrypto AES-GCM.
 */

// Generate or retrieve the encryption key from chrome.storage
async function getOrCreateKey() {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get(["_secure_k"], async (res) => {
      if (res._secure_k) {
        try {
          const rawKey = new Uint8Array(res._secure_k);
          const key = await crypto.subtle.importKey(
            "raw",
            rawKey,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
          );
          resolve(key);
        } catch (e) {
          reject(e);
        }
      } else {
        try {
          const key = await crypto.subtle.generateKey(
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
          );
          const exported = await crypto.subtle.exportKey("raw", key);
          const rawKeyArray = Array.from(new Uint8Array(exported));
          chrome.storage.local.set({ _secure_k: rawKeyArray }, () => {
            resolve(key);
          });
        } catch (e) {
          reject(e);
        }
      }
    });
  });
}

/**
 * Encrypts a string value using AES-GCM.
 */
async function encrypt(plainText) {
  try {
    const key = await getOrCreateKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    const encoded = encoder.encode(plainText);

    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      key,
      encoded
    );

    return {
      ciphertext: Array.from(new Uint8Array(encrypted)),
      iv: Array.from(iv)
    };
  } catch (e) {
    console.error("Encryption failed:", e);
    return null;
  }
}

/**
 * Decrypts an encrypted payload object { ciphertext, iv } back to plain text.
 */
async function decrypt(encryptedObj) {
  if (!encryptedObj || !encryptedObj.ciphertext || !encryptedObj.iv) {
    return null;
  }
  try {
    const key = await getOrCreateKey();
    const iv = new Uint8Array(encryptedObj.iv);
    const ciphertext = new Uint8Array(encryptedObj.ciphertext);

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      key,
      ciphertext
    );

    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  } catch (e) {
    console.error("Decryption failed:", e);
    return null;
  }
}

/**
 * Helper to encrypt an object.
 */
async function encryptObject(obj) {
  const jsonStr = JSON.stringify(obj);
  return await encrypt(jsonStr);
}

/**
 * Helper to decrypt an object.
 */
async function decryptObject(encryptedObj) {
  const decryptedStr = await decrypt(encryptedObj);
  if (!decryptedStr) return null;
  try {
    return JSON.parse(decryptedStr);
  } catch (e) {
    return null;
  }
}

// Export for Node/ES6/Browser/ServiceWorker compatibility
const targetGlobal = typeof window !== "undefined" ? window : (typeof self !== "undefined" ? self : globalThis);
if (typeof module !== "undefined" && module.exports) {
  module.exports = { encrypt, decrypt, encryptObject, decryptObject };
} else {
  targetGlobal.IdelyCrypto = { encrypt, decrypt, encryptObject, decryptObject };
}
