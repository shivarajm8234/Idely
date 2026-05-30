/**
 * NodeJS Verification Script for scanner.js
 */

const { scanText } = require("./scanner.js");

const testCases = [
  {
    name: "AWS Access Key ID",
    text: "AWS key is AKIAJHETRD6287FUDHSQ",
    expected: "AWS Access Key ID"
  },
  {
    name: "Google / Firebase API Key",
    text: "Firebase key AIzaSyB8K27dHskLskDkdJsk9832HdkslskDkdM",
    expected: "Google / Firebase API Key"
  },
  {
    name: "Stripe API Key",
    text: "Stripe token sk_test_thisIsAMockKeyForTestingPurposes",
    expected: "Stripe API Key"
  },
  {
    name: "GitHub Token",
    text: "GitHub secret is ghp_Ksd8Ksd8Ksd8Ksd8Ksd8Ksd8Ksd8Ksd8Ksd8",
    expected: "GitHub Token"
  },
  {
    name: "JSON Web Token",
    text: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE6MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    expected: "JSON Web Token (JWT)"
  }
];

let failed = 0;
for (const tc of testCases) {
  const results = scanText(tc.text, "test-suite");
  const found = results.find(r => r.type === tc.expected);
  if (found) {
    console.log(`\x1b[32m✅ Passed: ${tc.name}\x1b[0m`);
  } else {
    console.error(`\x1b[31m❌ Failed: ${tc.name}\x1b[0m. Got results:`, results);
    failed++;
  }
}

if (failed === 0) {
  console.log("\n\x1b[32;1m🎉 All scanning engine assertions passed successfully!\x1b[0m");
} else {
  console.error(`\n\x1b[31;1m🚨 ${failed} test cases failed.\x1b[0m`);
  process.exit(1);
}
