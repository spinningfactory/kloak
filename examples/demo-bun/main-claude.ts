/**
 * Mimics how Claude Code makes API calls over HTTPS using Bun's fetch().
 *
 * Claude Code is itself a Bun single-executable. It authenticates to the
 * Anthropic API by sending the API key as a Bearer token in the Authorization
 * header. This script reproduces that exact pattern against an in-cluster TLS
 * echo server so that the kloak e2e test can verify:
 *
 *   1. kloak's file-offset-based uprobe attaches to SSL_write in the stripped
 *      Bun binary (no exported symbols — the offset table is the only path).
 *   2. The shadow API key in the Authorization header is rewritten to the real
 *      key on the wire for the allowed host (getkloak.io/hosts matches).
 *   3. The blocked key is NOT rewritten when the host does not match.
 *
 * The echo server (kloak-tls-echo / tls-echo-server/server.py) responds to
 * GET /echo with a JSON body containing the full request headers, so the
 * rewritten value is visible in the pod logs.
 */

import * as fs from "fs";

// Disable TLS certificate verification — the echo server uses a self-signed
// cert generated at startup. Claude Code does the same for internal services.
process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0";

const PORT = 8443;

function loadSecret(envVar: string, fallback: string): string {
  const path = process.env[envVar];
  if (path) {
    try {
      return fs.readFileSync(path, "utf8").trimEnd();
    } catch {
      console.error(`Warning: could not read ${path}, using fallback`);
    }
  }
  return fallback;
}

async function callEchoAPI(
  host: string,
  apiKey: string,
  blockedKey: string,
  reqNum: number
): Promise<void> {
  const url = `https://${host}:${PORT}/echo`;
  try {
    const resp = await fetch(url, {
      method: "GET",
      headers: {
        // Primary secret — mimics Claude Code's API authentication.
        "Authorization": `Bearer ${apiKey}`,
        // Secondary header to test that a secret for a different host
        // is NOT rewritten (host-based filtering).
        "X-Blocked-Key": blockedKey,
        "User-Agent": "claude-code/test",
        "Content-Type": "application/json",
      },
    });

    const body = await resp.text();
    console.log(`\n--- Request #${reqNum} (target=${host}) status=${resp.status} ---`);
    console.log(`Echo: ${body}`);
  } catch (err) {
    console.error(`\n--- Request #${reqNum} ---\nError: ${err}`);
  }
}

async function main() {
  const apiKey = loadSecret("SECRET_API_KEY_FILE", "allowed-default-api-key");
  const blockedKey = loadSecret("SECRET_BLOCKED_KEY_FILE", "blocked-default-api-key");
  const targetHost = process.env["TARGET_HOST"] ?? "localhost";
  const intervalSec = parseInt(process.env["REQUEST_INTERVAL"] ?? "5", 10);

  console.log("============================================================");
  console.log(`demo-bun-claude: target=${targetHost}:${PORT} interval=${intervalSec}s`);
  console.log("============================================================");

  let reqNum = 0;
  while (true) {
    reqNum++;
    await callEchoAPI(targetHost, apiKey, blockedKey, reqNum);
    await Bun.sleep(intervalSec * 1000);
  }
}

main().catch((e) => {
  console.error("Fatal:", e);
  process.exit(1);
});
