// Package k8s implements secrets.Source over a Kubernetes informer
// cache. It joins the user-managed "enabled" Secrets with their
// kloak-managed shadow Secrets, parses the kloak annotations, and
// returns a flat snapshot suitable for the eBPF data plane.
package k8s

import (
	"context"
	"fmt"
	"sort"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/spinningfactory/kloak/pkg/secrets"
)

// Annotation / label keys understood by this adapter. Kept here (and
// duplicated as constants in pkg/controller) so the data-plane
// adapter does not depend on the controller package.
const (
	LabelEnabled = "getkloak.io/enabled"
	LabelManaged = "getkloak.io/managed"
	LabelOwner   = "getkloak.io/owner"

	AnnotationHosts = "getkloak.io/hosts"
	AnnotationPort  = "getkloak.io/port"

	ShadowSecretSuffix = "-kloak"
)

// filterAnnotations are the destination filters that are only honored
// as annotations. Hostnames and port specs are also valid label values,
// so `kubectl label secret foo getkloak.io/hosts=api.example.com` is
// accepted by the apiserver even though nothing reads it.
var filterAnnotations = []string{AnnotationHosts, AnnotationPort}

// MisplacedFilterLabels returns the destination-filter keys (hosts,
// port) that are set as labels instead of annotations, sorted. A filter
// set as a label is ignored, and an ignored filter means the secret may
// be sent to any destination, so callers must treat a non-empty result
// as a misconfiguration and fail closed rather than proceed unfiltered.
func MisplacedFilterLabels(labels map[string]string) []string {
	var out []string
	for _, k := range filterAnnotations {
		if _, ok := labels[k]; ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// Source implements secrets.Source by listing enabled and managed
// Secrets from a controller-runtime client and joining them in memory.
//
// The reader is typically the manager's cached client; calls to
// Snapshot are O(N) over the namespaces' Secret count and rely on the
// informer cache for staleness — same semantics as today's
// pkg/ebpf/sync.go::syncSecrets.
type Source struct {
	reader client.Reader
	log    *zap.SugaredLogger // optional; nil = silent
}

// NewSource returns a Source backed by the given client.Reader. A nil
// reader yields a source whose Snapshot always returns an empty slice
// (mirroring the no-op behavior pkg/ebpf has when its source is nil,
// e.g. cmd/ebpftest).
func NewSource(reader client.Reader) *Source {
	return &Source{reader: reader}
}

// WithLog attaches a logger so Snapshot can surface diagnostic output
// (e.g. invalid port annotations falling back to wildcard). Returns the
// receiver so call sites can chain the constructor.
func (s *Source) WithLog(log *zap.SugaredLogger) *Source {
	s.log = log
	return s
}

// Snapshot returns the currently effective set of secrets. Each entry
// is a (real, shadow) pair plus the host/IP/port filter parsed from
// the enabled Secret's annotations. Secrets without a corresponding
// shadow, or whose shadow is shorter than secrets.ShadowPrefixLen,
// are skipped (the same check pkg/ebpf/sync.go performs today before
// writing to the BPF map).
func (s *Source) Snapshot(ctx context.Context) ([]secrets.Secret, error) {
	if s.reader == nil {
		return nil, nil
	}

	var enabled corev1.SecretList
	if err := s.reader.List(ctx, &enabled, client.MatchingLabels{LabelEnabled: "true"}); err != nil {
		return nil, fmt.Errorf("list enabled secrets: %w", err)
	}

	var managed corev1.SecretList
	if err := s.reader.List(ctx, &managed, client.MatchingLabels{LabelManaged: "true"}); err != nil {
		return nil, fmt.Errorf("list managed secrets: %w", err)
	}

	// Build "namespace/<owner>-kloak" → *Secret index for the join.
	shadowByNN := make(map[string]*corev1.Secret, len(managed.Items))
	for i := range managed.Items {
		m := &managed.Items[i]
		shadowByNN[m.Namespace+"/"+m.Name] = m
	}

	out := make([]secrets.Secret, 0, len(enabled.Items))
	for i := range enabled.Items {
		en := &enabled.Items[i]
		shadowName := en.Name + ShadowSecretSuffix
		sh, ok := shadowByNN[en.Namespace+"/"+shadowName]
		if !ok {
			continue
		}

		// Fail closed: a filter set as a label would otherwise be
		// dropped and the secret synced with no destination restriction.
		// Skipping it means the app sends the placeholder, not the real
		// value. The validating webhook rejects this at admission; this
		// covers clusters where the webhook is missing or bypassed.
		if misplaced := MisplacedFilterLabels(en.Labels); len(misplaced) > 0 {
			if s.log != nil {
				s.log.Errorw("skipping secret: destination filter set as a label, must be an annotation",
					"namespace", en.Namespace, "secret", en.Name, "labels", misplaced)
			}
			continue
		}

		host, ip := secrets.ParseHost(en.Annotations[AnnotationHosts])
		var port uint16
		var proto uint8
		if raw, ok := en.Annotations[AnnotationPort]; ok && raw != "" {
			if ps, err := secrets.ParsePort(raw); err == nil {
				port = ps.Port
				proto = ps.Protocol
			} else if s.log != nil {
				// Bad annotation falls back to wildcard rather than failing
				// the whole snapshot. Surface it via the optional logger so
				// the operator can find and fix the manifest.
				//
				// TODO: this fails open (any port) when the validating
				// webhook is not installed. Skip the secret instead, like
				// MisplacedFilterLabels does, once callers can tolerate it.
				s.log.Warnw("invalid port annotation, treating as wildcard",
					"namespace", en.Namespace, "secret", en.Name,
					"annotation", AnnotationPort, "value", raw, "error", err)
			}
		}

		ownerID := en.Namespace + "/" + en.Name
		for key, real := range en.Data {
			shadowBytes, ok := sh.Data[key]
			if !ok {
				continue
			}
			if len(shadowBytes) < secrets.ShadowPrefixLen {
				continue
			}
			out = append(out, secrets.Secret{
				OwnerID:  ownerID,
				Key:      key,
				Real:     string(real),
				Shadow:   string(shadowBytes),
				Host:     host,
				IP:       ip,
				Port:     port,
				Protocol: proto,
			})
		}
	}
	return out, nil
}

// SeedShadowGenerator builds a prefix-occupancy seed from the cluster's
// existing managed shadow Secrets. Pass the result to
// secrets.NewShadowGenerator so freshly-minted shadows avoid colliding
// with anything already persisted.
//
// This was previously inline in pkg/controller/secret_reconciler.go;
// extracting it lets every k8s caller (today: the reconciler) share the
// same seeding logic.
func SeedShadowGenerator(ctx context.Context, reader client.Reader) (map[string]map[string]struct{}, error) {
	seed := make(map[string]map[string]struct{})
	if reader == nil {
		return seed, nil
	}
	var managed corev1.SecretList
	if err := reader.List(ctx, &managed, client.MatchingLabels{LabelManaged: "true"}); err != nil {
		return nil, fmt.Errorf("list managed secrets: %w", err)
	}
	for i := range managed.Items {
		shadow := &managed.Items[i]
		ownerName, ok := shadow.Labels[LabelOwner]
		if !ok || ownerName == "" {
			// Skip malformed managed shadows without an owner label —
			// otherwise multiple ownerless shadows would alias under
			// the same phantom "<namespace>/" key and pollute the
			// collision map.
			continue
		}
		ownerID := shadow.Namespace + "/" + ownerName
		for _, val := range shadow.Data {
			s := string(val)
			if len(s) < secrets.ShadowPrefixLen {
				continue
			}
			prefix := s[:secrets.ShadowPrefixLen]
			if seed[prefix] == nil {
				seed[prefix] = make(map[string]struct{})
			}
			seed[prefix][ownerID] = struct{}{}
		}
	}
	return seed, nil
}
