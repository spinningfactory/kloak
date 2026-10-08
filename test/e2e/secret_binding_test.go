//go:build e2e_ebpf

package e2e

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestSecretBindingRefusesUnreferencedSecret verifies that a pod can only
// redeem the secrets it references in its spec.
//
// The client pod mounts secret A. In one request it sends A's placeholder
// and secret B's placeholder, which the test reads from the API to stand in
// for a leaked one, to the echo server both secrets allow. A must arrive
// rewritten, B must arrive as its placeholder, and the controller must
// report the refused redemption with the pod and the secret.
func TestSecretBindingRefusesUnreferencedSecret(t *testing.T) {
	const (
		realA     = "REAL-BINDING-A-12345"
		realB     = "REAL-BINDING-B-67890"
		clientPod = "binding-client"
	)

	echoHost := deployTLSEchoServer(t)
	hosts := map[string]string{"getkloak.io/hosts": echoHost}
	createEnabledSecret(t, "binding-a", map[string][]byte{"api-key": []byte(realA)}, nil, hosts)
	createEnabledSecret(t, "binding-b", map[string][]byte{"api-key": []byte(realB)}, nil, hosts)
	assertShadowSecret(t, "binding-a", map[string][]byte{"api-key": []byte(realA)})
	shadowB := assertShadowSecret(t, "binding-b", map[string][]byte{"api-key": []byte(realB)})
	placeholderB := string(shadowB["api-key"])

	deployCipherClient(t, "binding-a", opensslClient{name: clientPod, image: "curlimages/curl:latest", chain: "4hop"})
	// Positive control: the pod's own secret is rewritten.
	waitForUprobeReady(t, clientPod, echoHost, realA)

	curlCmd := fmt.Sprintf(
		`curl --insecure --connect-timeout 10 -s -H "X-Secret: $(cat /etc/secrets/api-key)" -H %s https://%s:8443/echo`,
		shellQuote("X-Leaked: "+placeholderB), echoHost)
	var body string
	for attempt := 1; attempt <= 3; attempt++ {
		// Python's BaseHTTPServer closes without close_notify, so curl can exit
		// non-zero after receiving the full body; judge by the body.
		body, _ = kubectl("exec", "-n", testNamespace, clientPod, "--", "sh", "-c", curlCmd)
		if strings.Contains(body, `"headers"`) {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if !strings.Contains(body, `"headers"`) {
		t.Fatalf("echo server did not answer; output:\n%s", body)
	}

	if strings.Contains(body, realB) {
		t.Errorf("secret B was injected into a pod that does not reference it:\n%s", body)
	}
	if !strings.Contains(body, placeholderB) {
		t.Errorf("expected secret B's placeholder to reach the server unchanged:\n%s", body)
	}
	if !strings.Contains(body, realA) {
		t.Errorf("the pod's own secret A was not rewritten in the same request:\n%s", body)
	}

	// The controller reports the refusal, naming the pod and the secret.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	want := []string{"secret binding violation (rewrite refused)", testNamespace + "/" + clientPod, testNamespace + "/binding-b[api-key]"}
	for {
		logs, _ := kubectl("logs", "-n", kloakNamespace, "-l", "app.kubernetes.io/component=controller", "--tail=5000")
		if containsAll(logs, want...) {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("controller did not report the refused redemption (want %q); last logs:\n%s", want, lastLines(logs, 40))
		case <-time.After(pollInterval):
		}
	}
}

// shellQuote single-quotes s for sh.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
