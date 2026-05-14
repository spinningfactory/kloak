package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// loadSecret reads the secret value, preferring a direct env-var injection
// (envVar) over a file path read from fileEnvVar. The direct-env path is
// what the kloak webhook covers via `env[].valueFrom.secretKeyRef`
// rewriting (issue #96); the file path is the older volume-mount model.
// Keeping both lets the demo exercise either injection method without
// any code change — only the deployment manifest decides.
func loadSecret(envVar, fileEnvVar, defaultValue string) string {
	if val := os.Getenv(envVar); val != "" {
		log.Printf("Loaded secret from env var %s", envVar)
		return val
	}
	filePath := os.Getenv(fileEnvVar)
	if filePath != "" {
		content, err := os.ReadFile(filePath)
		if err == nil {
			log.Printf("Loaded secret from %s", filePath)
			return strings.TrimSpace(string(content))
		}
	}
	return defaultValue
}

func main() {
	// Load secrets. demo-go's deployment.yaml injects via
	// `env[].valueFrom.secretKeyRef` (env-var path), which exercises
	// the webhook's env rewriting plus the eBPF wire rewrite. Other
	// demos (demo-python, demo-js) still use the volume-mount path.
	keyAllowed := loadSecret("SECRET_ALLOWED", "SECRET_ALLOWED_FILE", "")
	keyBlocked := loadSecret("SECRET_BLOCKED", "SECRET_BLOCKED_FILE", "")

	targetURL := os.Getenv("TARGET_URL")
	if targetURL == "" {
		targetURL = "https://httpbin.org/headers"
	}

	intervalStr := os.Getenv("REQUEST_INTERVAL")
	interval := 10 * time.Second
	if intervalStr != "" {
		if d, err := time.ParseDuration(intervalStr + "s"); err == nil {
			interval = d
		}
	}

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("Kloak Demo (Go): Host Restriction Feature")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Target URL: %s\n\n", targetURL)
	fmt.Println("Secrets (as seen by the app - these are UUIDs if Kloak is working):")
	fmt.Printf("  Secret Allowed (httpbin.org): %s...\n", limitLen(keyAllowed, 30))
	fmt.Printf("  Secret Blocked (example.com): %s...\n\n", limitLen(keyBlocked, 30))
	fmt.Println("Expected behavior:")
	fmt.Println("  - X-Secret-Allowed: Should show ORIGINAL value in response")
	fmt.Println("  - X-Secret-Blocked: Should show UUID in response (not replaced)")
	fmt.Println(strings.Repeat("=", 60))

	// Brief delay for watched_hosts BPF map to be populated before first DNS query.
	fmt.Println("Waiting 10s for Kloak controller to sync...")
	time.Sleep(10 * time.Second)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	requestCount := 0
	for {
		requestCount++
		fmt.Printf("\n--- Request #%d ---\n", requestCount)

		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil {
			log.Printf("Error creating request: %v", err)
			continue
		}

		req.Header.Set("X-Secret-Allowed", keyAllowed)
		req.Header.Set("X-Secret-Blocked", keyBlocked)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", keyAllowed))

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Error: %v", err)
		} else {
			fmt.Printf("Status: %s\n", resp.Status)
			fmt.Println("Response headers echoed back by httpbin:")
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if len(body) > 800 {
				fmt.Println(string(body[:800]))
			} else {
				fmt.Println(string(body))
			}
		}

		fmt.Printf("\nWaiting %v before next request...\n", interval)
		time.Sleep(interval)
	}
}

func limitLen(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}
