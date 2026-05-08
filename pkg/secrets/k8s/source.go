// Package k8s implements secrets.Source over a Kubernetes informer
// cache. It joins the user-managed "enabled" Secrets with their
// kloak-managed shadow Secrets, parses the kloak annotations, and
// returns a flat snapshot suitable for the eBPF data plane.
package k8s

import (
	"context"
	"fmt"

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

// Source implements secrets.Source by listing enabled and managed
// Secrets from a controller-runtime client and joining them in memory.
//
// The reader is typically the manager's cached client; calls to
// Snapshot are O(N) over the namespaces' Secret count and rely on the
// informer cache for staleness — same semantics as today's
// pkg/ebpf/sync.go::syncSecrets.
type Source struct {
	reader client.Reader
}

// NewSource returns a Source backed by the given client.Reader. A nil
// reader yields a source whose Snapshot always returns an empty slice
// (mirroring the no-op behavior pkg/ebpf has when k8sReader is nil,
// e.g. cmd/ebpftest).
func NewSource(reader client.Reader) *Source {
	return &Source{reader: reader}
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

		host, ip := secrets.ParseHost(en.Annotations[AnnotationHosts])
		var port uint16
		var proto uint8
		if raw, ok := en.Annotations[AnnotationPort]; ok && raw != "" {
			if ps, err := secrets.ParsePort(raw); err == nil {
				port = ps.Port
				proto = ps.Protocol
			}
			// On parse error, fall through to wildcard. Today's
			// pkg/ebpf/sync.go logs the error and does the same;
			// an adapter shouldn't fail the whole snapshot for a
			// single bad annotation.
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
		ownerID := shadow.Namespace + "/" + shadow.Labels[LabelOwner]
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
