/**
 * Demo JavaScript Application for Kloak - Host Restriction Demo
 *
 * This app demonstrates the host restriction feature by using TWO secrets:
 * 1. secret-allowed: Configured with getkloak.io/hosts=httpbin.org (will be replaced)
 * 2. secret-blocked: Configured with getkloak.io/hosts=example.com (will NOT be replaced)
 *
 * When making requests to httpbin.org:
 * - X-Secret-Allowed header will show the ORIGINAL value (replaced by Kloak)
 * - X-Secret-Blocked header will show the UUID (NOT replaced, wrong host)
 */

const fs = require("fs");
const https = require("https");

function loadSecret(envVar, defaultValue) {
  const filePath = process.env[envVar];
  if (filePath) {
    try {
      const value = fs.readFileSync(filePath, "utf8").trim();
      console.log(`Loaded secret from ${filePath}`);
      return value;
    } catch (_) {
      // fall through to default
    }
  }
  return defaultValue;
}

function makeRequest(url, headers) {
  return new Promise((resolve, reject) => {
    const opts = new URL(url);
    const reqOpts = {
      hostname: opts.hostname,
      port: opts.port || 443,
      path: opts.pathname + opts.search,
      method: "GET",
      headers,
    };

    const req = https.request(reqOpts, (res) => {
      let body = "";
      res.on("data", (chunk) => (body += chunk));
      res.on("end", () => resolve({ status: res.statusCode, body }));
    });
    req.on("error", reject);
    req.setTimeout(10000, () => {
      req.destroy(new Error("request timeout"));
    });
    req.end();
  });
}

async function main() {
  const keyAllowed = loadSecret("SECRET_ALLOWED_FILE", "allowed-default-key");
  const keyBlocked = loadSecret("SECRET_BLOCKED_FILE", "blocked-default-key");
  const targetURL =
    process.env.TARGET_URL || "https://httpbin.org/headers";
  const interval = parseInt(process.env.REQUEST_INTERVAL || "10", 10) * 1000;

  console.log("=".repeat(60));
  console.log("Kloak Demo (JS): Host Restriction Feature");
  console.log("=".repeat(60));
  console.log(`Target URL: ${targetURL}\n`);
  console.log(
    "Secrets (as seen by the app - these are UUIDs if Kloak is working):"
  );
  console.log(
    `  Secret Allowed (httpbin.org): ${keyAllowed.substring(0, 30)}...`
  );
  console.log(
    `  Secret Blocked (example.com): ${keyBlocked.substring(0, 30)}...`
  );
  console.log("\nExpected behavior:");
  console.log("  - X-Secret-Allowed: Should show ORIGINAL value in response");
  console.log(
    "  - X-Secret-Blocked: Should show UUID in response (not replaced)"
  );
  console.log("=".repeat(60));

  // Brief delay for kloak controller to attach uprobes before the first
  // TLS connection. Node's https.globalAgent defaults to keepAlive=true
  // (and we send Connection: keep-alive explicitly below), so all
  // subsequent requests reuse the very first connection's SSL_CTX. If
  // we lose the attach race against that first connection, every later
  // request misses the rewrite — observable in CI as the kprobe_walk
  // counter staying frozen while the demo cycles 100+ requests.
  // Mirrors examples/demo-go/main.go:55-57.
  console.log("Waiting 10s for Kloak controller to sync...");
  await new Promise((r) => setTimeout(r, 10000));

  let requestCount = 0;
  while (true) {
    requestCount++;
    console.log(`\n--- Request #${requestCount} ---`);

    try {
      const headers = {
        "X-Secret-Allowed": keyAllowed,
        "X-Secret-Blocked": keyBlocked,
        Authorization: `Bearer ${keyAllowed}`,
        // Padding headers to match Python requests library size (~280 bytes total).
        "User-Agent": "node-demo/1.0.0",
        "Accept-Encoding": "gzip, deflate",
        Accept: "*/*",
        Connection: "keep-alive",
      };

      const { status, body } = await makeRequest(targetURL, headers);
      console.log(`Status: ${status}`);
      console.log("Response headers echoed back by httpbin:");
      console.log(body.substring(0, 800));
    } catch (err) {
      console.log(`Error: ${err.message}`);
    }

    console.log(
      `\nWaiting ${interval / 1000}s before next request...`
    );
    await new Promise((r) => setTimeout(r, interval));
  }
}

main();
