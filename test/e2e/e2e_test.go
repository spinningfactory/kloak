package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	kloakNamespace = "kloak-system"
	testNamespace  = "kloak-e2e"
	defaultTimeout = 120 * time.Second
	pollInterval   = 2 * time.Second
)

var (
	clientset *kubernetes.Clientset
	repoRoot  string
	chartDir  string // path to the Helm chart directory
)

// findRepoRoot returns the absolute path to the repository root
// by looking for go.mod starting from the test directory.
func findRepoRoot() (string, error) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to find module root: %w\n%s", err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

func TestMain(m *testing.M) {
	var err error
	repoRoot, err = findRepoRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to find repo root: %v\n", err)
		os.Exit(1)
	}

	// Build kubeconfig
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		home, _ := os.UserHomeDir()
		kubeconfig = filepath.Join(home, ".kube", "config")
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build kubeconfig: %v\n", err)
		os.Exit(1)
	}

	clientset, err = kubernetes.NewForConfig(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create clientset: %v\n", err)
		os.Exit(1)
	}

	// Create namespace and deploy OTel Collector for metrics e2e testing
	if _, err := kubectl("create", "namespace", kloakNamespace, "--dry-run=client", "-o", "yaml"); err == nil {
		_, _ = kubectl("create", "namespace", kloakNamespace)
	}
	collectorManifest := filepath.Join(repoRoot, "test", "e2e", "otel-collector.yaml")
	if _, err := kubectl("apply", "-f", collectorManifest, "-n", kloakNamespace); err != nil {
		fmt.Fprintf(os.Stderr, "failed to deploy otel-collector: %v\n", err)
		os.Exit(1)
	}

	// Deploy Kloak using Helm chart
	chartDir = filepath.Join(repoRoot, "charts", "kloak")
	valuesFile := filepath.Join(repoRoot, "test", "e2e", "values-e2e.yaml")
	if _, err := helm("install", "kloak", chartDir, "-n", kloakNamespace, "--create-namespace", "-f", valuesFile, "--wait", "--timeout", "120s"); err != nil {
		fmt.Fprintf(os.Stderr, "failed to deploy kloak: %v\n", err)
		os.Exit(1)
	}

	// Wait for controller and webhook to be ready
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	fmt.Println("Waiting for kloak-controller DaemonSet...")
	if err := waitForDaemonSetReady(ctx, kloakNamespace, "kloak-controller"); err != nil {
		fmt.Fprintf(os.Stderr, "controller not ready: %v\n", err)
		dumpLogs()
		teardown()
		os.Exit(1)
	}

	fmt.Println("Waiting for kloak-webhook Deployment...")
	if err := waitForDeploymentReady(ctx, kloakNamespace, "kloak-webhook"); err != nil {
		fmt.Fprintf(os.Stderr, "webhook not ready: %v\n", err)
		dumpLogs()
		teardown()
		os.Exit(1)
	}

	fmt.Println("Waiting for otel-collector Deployment...")
	if err := waitForDeploymentReady(ctx, kloakNamespace, "otel-collector"); err != nil {
		fmt.Fprintf(os.Stderr, "otel-collector not ready: %v\n", err)
		dumpLogs()
		teardown()
		os.Exit(1)
	}

	// Create test namespace with getkloak.io/enabled=true
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNamespace,
			Labels: map[string]string{
				"getkloak.io/enabled": "true",
			},
		},
	}
	if _, err := clientset.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{}); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create test namespace: %v\n", err)
		teardown()
		os.Exit(1)
	}

	fmt.Println("Kloak deployed and ready. Running tests...")
	code := m.Run()

	teardown()
	os.Exit(code)
}

func teardown() {
	// Delete test namespace (cascade deletes all resources in it)
	_ = clientset.CoreV1().Namespaces().Delete(context.Background(), testNamespace, metav1.DeleteOptions{})
	// Remove kloak deployment. The controller exits cleanly, flushing
	// coverage data to the hostPath volume (/tmp/kloak-coverage on the
	// k3d node) which CI copies after teardown.
	_, _ = helm("uninstall", "kloak", "-n", kloakNamespace)
}

func dumpLogs() {
	fmt.Println("=== Kloak Controller Logs (previous) ===")
	out, _ := kubectl("logs", "-n", kloakNamespace, "-l", "app.kubernetes.io/component=controller", "--tail=50", "--previous")
	fmt.Println(out)
	fmt.Println("=== Kloak Controller Logs ===")
	out, _ = kubectl("logs", "-n", kloakNamespace, "-l", "app.kubernetes.io/component=controller", "--tail=50")
	fmt.Println(out)
	fmt.Println("=== Kloak Webhook Logs ===")
	out, _ = kubectl("logs", "-n", kloakNamespace, "-l", "app.kubernetes.io/component=webhook", "--tail=50")
	fmt.Println(out)
	fmt.Println("=== OTel Collector Logs ===")
	out, _ = kubectl("logs", "-n", kloakNamespace, "-l", "app=otel-collector", "--tail=50")
	fmt.Println(out)
	fmt.Println("=== All Pods ===")
	out, _ = kubectl("get", "pods", "-A")
	fmt.Println(out)
}
