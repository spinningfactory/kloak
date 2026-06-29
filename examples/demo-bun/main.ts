/**
 * Minimal Bun raw-TLS client for kloak e2e testing.
 *
 * Mirrors examples/demo-boringssl/main.c but implemented in TypeScript using
 * Bun's built-in TLS socket API. Resolves TARGET_HOST via DNS (populating
 * kloak's dns_ip_map), connects to port 8443, and sends a raw TLS payload:
 *
 *   ALLOWED=<secret>\nBLOCKED=<secret>\n
 *
 * The allowed secret's kloak Secret has getkloak.io/hosts set to this echo
 * Service, so the kernel rewrites the shadow placeholder to the real value on
 * the wire. The echo server returns whatever it received; we print it so the
 * e2e test can assert the real ALLOWED value appears and the BLOCKED one does not.
 *
 * SSL_write (inside Bun's statically linked BoringSSL) is the function kloak
 * attaches its uprobe to via file offset — the whole point of this demo is to
 * exercise the Bun file-offset attach path and the BoringSSL H-extraction chain.
 */

import * as fs from "fs";
import * as tls from "tls";

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

async function sendAndEcho(
  host: string,
  secretAllowed: string,
  secretBlocked: string,
  reqNum: number
): Promise<void> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host,
        port: PORT,
        rejectUnauthorized: false,
        // Pin AES-128-GCM so kloak's GCM rewrite path is exercised.
        ciphers: "TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256",
        minVersion: "TLSv1.2",
      },
      () => {
        const payload = `ALLOWED=${secretAllowed}\nBLOCKED=${secretBlocked}\n`;
        socket.write(payload);
      }
    );

    socket.on("data", (data: Buffer) => {
      const echo = data.toString().trimEnd();
      console.log(`\n--- Request #${reqNum} (target=${host}) ---`);
      console.log(`Echo: ${echo}`);
      socket.end();
      resolve();
    });

    socket.on("error", (err: Error) => {
      console.error(`\n--- Request #${reqNum} ---\nError: ${err.message}`);
      resolve();
    });

    socket.setTimeout(10000, () => {
      console.error(`\n--- Request #${reqNum} ---\nError: connection timed out`);
      socket.destroy();
      resolve();
    });
  });
}

async function main() {
  const secretAllowed = loadSecret("SECRET_ALLOWED_FILE", "allowed-default-key");
  const secretBlocked = loadSecret("SECRET_BLOCKED_FILE", "blocked-default-key");
  const targetHost = process.env.TARGET_HOST ?? "localhost";
  const intervalSec = parseInt(process.env.REQUEST_INTERVAL ?? "2", 10);

  console.log("============================================================");
  console.log(`demo-bun: target=${targetHost}:${PORT} interval=${intervalSec}s`);
  console.log("============================================================");

  let reqNum = 0;
  while (true) {
    reqNum++;
    await sendAndEcho(targetHost, secretAllowed, secretBlocked, reqNum);
    await Bun.sleep(intervalSec * 1000);
  }
}

main().catch((e) => {
  console.error("Fatal:", e);
  process.exit(1);
});
