/**
 * Demo Java Application for Kloak - Host Restriction Demo
 *
 * This app demonstrates the host restriction feature by using TWO secrets:
 * 1. secret-allowed: Configured with getkloak.io/hosts=httpbin.org (will be replaced)
 * 2. secret-blocked: Configured with getkloak.io/hosts=example.com (will NOT be replaced)
 *
 * When making requests to httpbin.org:
 * - X-Secret-Allowed header will show the ORIGINAL value (replaced by Kloak)
 * - X-Secret-Blocked header will show the UUID (NOT replaced, wrong host)
 *
 * No custom truststore code is needed - JAVA_TOOL_OPTIONS is injected by Kloak.
 */

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;

public class DemoApp {

    static String loadSecret(String envVar, String defaultValue) {
        String filePath = System.getenv(envVar);
        if (filePath != null && !filePath.isEmpty()) {
            try {
                String value = Files.readString(Path.of(filePath)).trim();
                System.out.println("Loaded secret from " + filePath);
                return value;
            } catch (IOException e) {
                // fall through to default
            }
        }
        return defaultValue;
    }

    static String doGet(String targetURL, String keyAllowed, String keyBlocked) throws IOException {
        URL url = new URL(targetURL);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);
        conn.setRequestProperty("X-Secret-Allowed", keyAllowed);
        conn.setRequestProperty("X-Secret-Blocked", keyBlocked);
        conn.setRequestProperty("Authorization", "Bearer " + keyAllowed);

        int status = conn.getResponseCode();
        StringBuilder body = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(status >= 400 ? conn.getErrorStream() : conn.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                body.append(line).append("\n");
            }
        } finally {
            conn.disconnect();
        }

        return "Status: " + status + "\nResponse headers echoed back by httpbin:\n"
                + body.substring(0, Math.min(800, body.length()));
    }

    public static void main(String[] args) throws InterruptedException {
        String keyAllowed = loadSecret("SECRET_ALLOWED_FILE", "allowed-default-key");
        String keyBlocked = loadSecret("SECRET_BLOCKED_FILE", "blocked-default-key");
        String targetURL = System.getenv().getOrDefault("TARGET_URL", "https://httpbin.org/headers");
        int interval = Integer.parseInt(System.getenv().getOrDefault("REQUEST_INTERVAL", "10")) * 1000;

        System.out.println("=".repeat(60));
        System.out.println("Kloak Demo (Java): Host Restriction Feature");
        System.out.println("=".repeat(60));
        System.out.println("Target URL: " + targetURL);
        System.out.println();
        System.out.println("Secrets (as seen by the app - these are UUIDs if Kloak is working):");
        System.out.println("  Secret Allowed (httpbin.org): " + keyAllowed.substring(0, Math.min(30, keyAllowed.length())) + "...");
        System.out.println("  Secret Blocked (example.com): " + keyBlocked.substring(0, Math.min(30, keyBlocked.length())) + "...");
        System.out.println();
        System.out.println("Expected behavior:");
        System.out.println("  - X-Secret-Allowed: Should show ORIGINAL value in response");
        System.out.println("  - X-Secret-Blocked: Should show UUID in response (not replaced)");
        System.out.println("=".repeat(60));

        // Print truststore config for debugging
        String javaToolOpts = System.getenv("JAVA_TOOL_OPTIONS");
        System.out.println("JAVA_TOOL_OPTIONS: " + (javaToolOpts != null ? javaToolOpts : "<not set>"));
        String trustStore = System.getProperty("javax.net.ssl.trustStore");
        System.out.println("javax.net.ssl.trustStore: " + (trustStore != null ? trustStore : "<default>"));

        // Startup delay to wait for Kloak controller to sync
        System.out.println("Waiting 15s for Kloak controller to sync...");
        Thread.sleep(15000);

        int requestCount = 0;

        while (true) {
            requestCount++;
            System.out.println("\n--- Request #" + requestCount + " ---");

            try {
                System.out.println(doGet(targetURL, keyAllowed, keyBlocked));
            } catch (Exception e) {
                // Print full exception chain for clear diagnostics
                System.out.println("Error: " + e);
                Throwable cause = e.getCause();
                while (cause != null) {
                    System.out.println("  Caused by: " + cause);
                    cause = cause.getCause();
                }
            }

            System.out.println("\nWaiting " + (interval / 1000) + "s before next request...");
            Thread.sleep(interval);
        }
    }
}
