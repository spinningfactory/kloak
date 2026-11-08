//go:build e2e_ebpf

package e2e

import (
	"fmt"
	"strings"
	"testing"
)

// TestPrescanDecoys sends, in one TLS write, placeholder lookalikes that are
// not in the secret table before a real placeholder: a literal kl:: (four
// times, the number of match slots, and more), kl:: followed by 4 characters
// one character off the real key, and the HPACK Huffman prefix of kl::. Only
// placeholders in the secret table may take one of the prescan's match slots,
// so the real placeholder is still rewritten, and the decoys go out unchanged.
func TestPrescanDecoys(t *testing.T) {
	secretValue := "REAL-PRESCAN-DECOY-12345"
	secretName := "prescan-decoy-secret"

	echoSvcHost := deployTLSEchoServer(t)
	createEnabledSecret(t, secretName, map[string][]byte{
		"api-key": []byte(secretValue),
	}, nil, map[string]string{
		"getkloak.io/hosts": echoSvcHost,
	})
	shadow := string(assertShadowSecret(t, secretName, map[string][]byte{
		"api-key": []byte(secretValue),
	})["api-key"])

	client := opensslClient{name: "prescan-decoy-client", image: "curlimages/curl:latest", chain: "4hop"}
	clientPod := deployCipherClient(t, secretName, client)
	waitForUprobeReady(t, clientPod, echoSvcHost, secretValue)

	// kl:: plus the real key's 4 characters, the last one changed.
	lookalike := []byte(shadow[:8])
	if lookalike[7] == 'Z' {
		lookalike[7] = 'Y'
	} else {
		lookalike[7] = 'Z'
	}
	// curl sends the headers in the order given, in one TLS write.
	curlCmd := fmt.Sprintf(
		`SECRET=$(cat /etc/secrets/api-key) && HUFF=$(printf '\353\105\313') && `+
			`curl --insecure --connect-timeout 10 -s `+
			`-H "X-Decoy: kl::aaaa kl::bbbb kl::cccc kl::dddd kl::eeee" `+
			`-H "X-Lookalike: %s" `+
			`-H "X-Huffman: ${HUFF}abcde" `+
			`-H "X-Secret: $SECRET" https://%s:8443/echo`,
		lookalike, echoSvcHost,
	)

	var out string
	for attempt := 1; attempt <= 3; attempt++ {
		out, _ = kubectl("exec", "-n", testNamespace, clientPod, "--", "sh", "-c", curlCmd)
		// The echo server may close without close_notify (curl exit 56)
		// after sending the full response; see execCurl.
		if strings.Contains(out, `"headers"`) {
			break
		}
		t.Logf("curl attempt %d: out=%q", attempt, out)
	}
	if !strings.Contains(out, `"headers"`) {
		t.Fatalf("echo server did not return valid JSON; output:\n%s", out)
	}
	if !strings.Contains(out, secretValue) {
		t.Errorf("real secret not in echo response: the placeholder after the decoys was not rewritten:\n%s", out)
	}
	if strings.Contains(out, shadow) {
		t.Errorf("placeholder reached the server unchanged:\n%s", out)
	}
	for _, decoy := range []string{"kl::aaaa kl::bbbb kl::cccc kl::dddd kl::eeee", string(lookalike)} {
		if !strings.Contains(out, decoy) {
			t.Errorf("decoy %q not echoed unchanged:\n%s", decoy, out)
		}
	}
}
