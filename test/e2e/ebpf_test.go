//go:build e2e_ebpf

package e2e

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ebpfRewriteTest describes a single eBPF rewrite test case for a specific runtime.
type ebpfRewriteTest struct {
	// name is the subtest name (e.g. "go", "python", "js")
	name string
	// demoDir is the directory under examples/ containing deployment.yaml and Dockerfile
	demoDir string
	// deploymentName is the Kubernetes Deployment name
	deploymentName string
	// appLabel is the label selector for the demo app pods
	appLabel string
	// startupWait is extra time to wait after deployment ready for the app to make requests
	startupWait time.Duration
}

var ebpfTests = []ebpfRewriteTest{
	{
		name:           "go",
		demoDir:        "demo-go",
		deploymentName: "demo-go",
		appLabel:       "app=demo-go",
		startupWait:    45 * time.Second, // 15s startup delay + request cycles
	},
	{
		name:           "python",
		demoDir:        "demo-python",
		deploymentName: "demo-python",
		appLabel:       "app=demo-python",
		startupWait:    30 * time.Second,
	},
	{
		name:           "js",
		demoDir:        "demo-js",
		deploymentName: "demo-js",
		appLabel:       "app=demo-js",
		startupWait:    30 * time.Second,
	},
	{
		name:           "go-boringssl",
		demoDir:        "demo-go-boring",
		deploymentName: "demo-go-boring",
		appLabel:       "app=demo-go-boring",
		startupWait:    45 * time.Second,
	},
}

func TestEBPFSecretRewrite(t *testing.T) {
	// Create secrets shared by all demo apps.
	// Key must be "api-key" to match deployment volume mount paths.
	allowedData := map[string][]byte{"api-key": []byte("REAL-ALLOWED-KEY-12345")}
	blockedData := map[string][]byte{"api-key": []byte("REAL-BLOCKED-KEY-67890")}

	createEnabledSecret(t, "secret-allowed", allowedData, map[string]string{
		"getkloak.io/hosts": "httpbin.org",
	})
	createEnabledSecret(t, "secret-blocked", blockedData, map[string]string{
		"getkloak.io/hosts": "example.com",
	})

	assertShadowSecret(t, "secret-allowed", allowedData)
	assertShadowSecret(t, "secret-blocked", blockedData)

	for _, tc := range ebpfTests {
		t.Run(tc.name, func(t *testing.T) {
			runEBPFRewriteTest(t, tc)
		})
	}
}

func runEBPFRewriteTest(t *testing.T, tc ebpfRewriteTest) {
	// Deploy the demo app
	demoManifest := filepath.Join(repoRoot, "examples", tc.demoDir, "deployment.yaml")
	_, err := kubectl("apply", "-f", demoManifest, "-n", testNamespace)
	if err != nil {
		t.Fatalf("failed to deploy %s: %v", tc.demoDir, err)
	}
	t.Cleanup(func() {
		_, _ = kubectl("delete", "-f", demoManifest, "-n", testNamespace, "--ignore-not-found")
	})

	// Wait for deployment ready
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if err := waitForDeploymentReady(ctx, testNamespace, tc.deploymentName); err != nil {
		demoDesc, _ := kubectl("describe", "deployment", "-n", testNamespace, tc.deploymentName)
		t.Logf("deployment describe:\n%s", demoDesc)
		t.Fatalf("%s not ready: %v", tc.deploymentName, err)
	}

	// Dump controller logs to see uprobe attachment
	ctrlLogs, _ := kubectl("logs", "-n", kloakNamespace, "-l", "app.kubernetes.io/component=controller", "--tail=50")
	t.Logf("=== Controller logs (after deploy %s) ===\n%s", tc.name, ctrlLogs)

	// Wait for startup + request cycles
	t.Logf("Waiting %s for %s to make requests...", tc.startupWait, tc.name)
	time.Sleep(tc.startupWait)

	// Read demo app logs
	out, err := kubectl("logs", "-n", testNamespace, "-l", tc.appLabel, "--tail=50")
	if err != nil {
		t.Fatalf("failed to read %s logs: %v", tc.name, err)
	}
	t.Logf("=== %s demo app logs ===\n%s", tc.name, out)

	// Dump controller logs after requests
	ctrlLogsAfter, _ := kubectl("logs", "-n", kloakNamespace, "-l", "app.kubernetes.io/component=controller", "--tail=50")
	t.Logf("=== Controller logs (after %s requests) ===\n%s", tc.name, ctrlLogsAfter)

	// Verify the allowed secret was rewritten to the real value
	if !strings.Contains(out, "REAL-ALLOWED-KEY-12345") {
		t.Errorf("[%s] logs should contain the real allowed secret (eBPF should have replaced kloak:UUID)", tc.name)
	}

	// Verify the blocked secret was NOT rewritten (wrong host restriction)
	if strings.Contains(out, "REAL-BLOCKED-KEY-67890") {
		t.Errorf("[%s] logs should NOT contain the real blocked secret (host restriction should prevent replacement)", tc.name)
	}

	// Clean up deployment before next subtest to free resources
	_, _ = kubectl("delete", "-f", demoManifest, "-n", testNamespace, "--ignore-not-found")
	// Brief wait for pod termination
	time.Sleep(5 * time.Second)
}
