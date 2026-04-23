package webhook

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	// LabelHosts is the CSV list of hostnames a secret may be sent to.
	LabelHosts = "getkloak.io/hosts"
	// LabelPort restricts a secret to a specific port (or port/proto).
	LabelPort = "getkloak.io/port"

	// maxHostLen mirrors MAX_HOST_LEN in pkg/ebpf/bpf/tls_uprobe.c.
	// The BPF filter compares with `host_len < MAX_HOST_LEN`, so a host
	// exactly MAX_HOST_LEN bytes would bypass filtering — we cap at 63.
	maxHostLen = 63

	// minDataLen mirrors SECRET_KEY_LEN in pkg/ebpf/bpf/tls_uprobe.c and
	// ShadowPrefixLen in pkg/controller/secret_reconciler.go. The BPF
	// program looks up the first 8 bytes; shorter secrets cannot be keyed
	// and the reconciler refuses to generate a shadow.
	minDataLen = 8

	// maxDataLen mirrors SECRET_MAX_LEN in pkg/ebpf/bpf/tls_uprobe.c.
	// sync.go silently truncates values longer than this when populating
	// the BPF map, producing wrong rewrites on the wire. We reject here
	// so the user sees the problem at apply time.
	maxDataLen = 128
)

// SecretValidator is a ValidatingAdmissionWebhook for kloak-enabled Secrets.
// It rejects configurations that would silently bypass runtime filters
// (e.g. a host label longer than the BPF map can compare).
type SecretValidator struct {
	decoder admission.Decoder
	log     *zap.SugaredLogger
}

func NewSecretValidator(log *zap.SugaredLogger) *SecretValidator {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	return &SecretValidator{
		decoder: admission.NewDecoder(scheme),
		log:     log,
	}
}

// Handle validates a Secret admission request. Non-kloak-enabled secrets are
// allowed through unchanged; the webhook should also be scoped with an
// objectSelector on `getkloak.io/enabled=true`.
func (v *SecretValidator) Handle(ctx context.Context, req admission.Request) admission.Response { //nolint:gocritic // hugeParam: interface requirement
	secret := &corev1.Secret{}
	if err := v.decoder.Decode(req, secret); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	if secret.Labels[LabelEnabled] != "true" {
		return admission.Allowed("not kloak-enabled")
	}

	if err := validateHostsLabel(secret.Labels[LabelHosts]); err != nil {
		v.log.Warnw("rejecting secret: invalid hosts label",
			"namespace", secret.Namespace, "name", secret.Name, "error", err)
		return admission.Denied(fmt.Sprintf("kloak: invalid %s label: %v", LabelHosts, err))
	}

	if err := validatePortLabel(secret.Labels[LabelPort]); err != nil {
		v.log.Warnw("rejecting secret: invalid port label",
			"namespace", secret.Namespace, "name", secret.Name, "error", err)
		return admission.Denied(fmt.Sprintf("kloak: invalid %s label: %v", LabelPort, err))
	}

	if err := validateSecretData(secret.Data, secret.StringData); err != nil {
		v.log.Warnw("rejecting secret: invalid data",
			"namespace", secret.Namespace, "name", secret.Name, "error", err)
		return admission.Denied(fmt.Sprintf("kloak: %v", err))
	}

	return admission.Allowed("valid")
}

// validateSecretData enforces the length constraints that the BPF pipeline
// imposes on secret values. The reconciler refuses to create a shadow if
// any entry is shorter than minDataLen (so the secret never gets rewritten
// and pods mounting it are blocked by the mutating webhook with a confusing
// "shadow not found" error). sync.go silently truncates entries longer than
// maxDataLen, producing incorrect rewrites on the wire. Surface both at
// admission time.
//
// stringData is merged into data by the apiserver; we check both to cover
// the case where the webhook sees the pre-merged object.
func validateSecretData(data map[string][]byte, stringData map[string]string) error {
	if len(data) == 0 && len(stringData) == 0 {
		return fmt.Errorf("secret has no data entries — nothing for kloak to rewrite")
	}

	// Effective per-key size. stringData takes precedence over data when
	// both contain the same key (matches apiserver merge semantics).
	sizes := make(map[string]int, len(data)+len(stringData))
	for k, v := range data {
		sizes[k] = len(v)
	}
	for k, v := range stringData {
		sizes[k] = len(v)
	}

	for k, n := range sizes {
		if n < minDataLen {
			return fmt.Errorf("data[%q] is %d bytes, minimum %d required (BPF key lookup)", k, n, minDataLen)
		}
		if n > maxDataLen {
			return fmt.Errorf("data[%q] is %d bytes, maximum %d allowed (BPF rewrite would truncate)", k, n, maxDataLen)
		}
	}
	return nil
}

// validateHostsLabel validates the single host or IP in the getkloak.io/hosts
// label. Today only one host per secret is supported by the BPF data plane;
// multi-host support was present in an earlier version but broke during a
// rewrite and has not been restored. When it comes back, the CSV rejection
// below should be relaxed.
//
// Accepted forms:
//   - "" — no host filter (allow any destination)
//   - "*" — explicit wildcard (same as empty)
//   - a single RFC 1123 DNS subdomain, ≤ maxHostLen bytes
//   - an IPv4 or IPv6 address
//
// Note: k8s label values already restrict chars to [A-Za-z0-9._-] and length
// to 63, so a comma would normally be rejected at the API layer before this
// validator runs. We still check here to give a clear error message if the
// label source ever changes (e.g. annotation-based config) and to document
// intent to the next reader.
func validateHostsLabel(hosts string) error {
	if hosts == "" {
		return nil
	}
	if strings.Contains(hosts, ",") {
		return fmt.Errorf("multiple hosts are not supported yet — specify a single hostname, IP, or '*' for any")
	}
	h := strings.TrimSpace(hosts)
	if h == "" {
		return fmt.Errorf("empty host value")
	}
	if h == "*" {
		return nil
	}
	if len(h) > maxHostLen {
		return fmt.Errorf("host %q exceeds max length %d bytes", h, maxHostLen)
	}
	if net.ParseIP(h) != nil {
		return nil
	}
	if errs := validation.IsDNS1123Subdomain(h); len(errs) != 0 {
		return fmt.Errorf("host %q is not a valid DNS name: %s", h, strings.Join(errs, "; "))
	}
	return nil
}

// validatePortLabel accepts "" (no filter), "PORT", or "PORT/PROTO" where
// PORT ∈ [1, 65535] and PROTO ∈ {tcp, udp}. Kept in sync with the parser in
// pkg/ebpf/sync.go — duplicated to avoid a webhook→ebpf package dependency.
func validatePortLabel(spec string) error {
	if spec == "" {
		return nil
	}
	s := strings.ToLower(strings.TrimSpace(spec))
	parts := strings.Split(s, "/")
	if len(parts) == 0 || len(parts) > 2 {
		return fmt.Errorf("invalid format %q, expected PORT or PORT/PROTO", spec)
	}
	p, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return fmt.Errorf("invalid port %q: %w", parts[0], err)
	}
	if p == 0 {
		return fmt.Errorf("invalid port: must be in range [1, 65535]")
	}
	if len(parts) == 2 {
		switch parts[1] {
		case "tcp", "udp":
		default:
			return fmt.Errorf("invalid proto %q (must be tcp or udp)", parts[1])
		}
	}
	return nil
}
