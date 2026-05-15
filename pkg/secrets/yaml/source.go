package yaml

import (
	"context"
	"fmt"
	"os"

	"sigs.k8s.io/yaml"

	"github.com/spinningfactory/kloak/pkg/secrets"
)

// Source implements secrets.Source over a kloak-native YAML file.
//
// The file is loaded, validated, and translated at construction; the
// resulting []secrets.Secret is cached and returned by every Snapshot
// call. Hot reload is not implemented in this Source — wrap it in a
// reloading shim when Phase 6's Subscribe() variant lands.
//
// Source is safe for concurrent Snapshot callers because the snapshot
// slice is immutable after New returns.
type Source struct {
	snapshot []secrets.Secret
}

// NewSource reads, parses, validates, and translates the YAML at path.
// All errors — file not found, invalid YAML, schema violations, port
// parse errors, Huffman-unsatisfiable shadow generation — surface here,
// not at Snapshot time. The runtime can therefore decide to fail fast
// before launching a child process.
func NewSource(path string) (*Source, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read secrets file: %w", err)
	}
	var spec fileSpec
	// sigs.k8s.io/yaml routes through encoding/json for stricter type
	// handling than gopkg.in/yaml.v3 — it rejects an int where a string
	// is expected, which matches user expectations for a config file.
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		return nil, fmt.Errorf("parse secrets file: %w", err)
	}

	gen := secrets.NewShadowGenerator(nil, nil)
	out, err := translate(spec, gen)
	if err != nil {
		return nil, err
	}
	return &Source{snapshot: out}, nil
}

// Snapshot returns the cached snapshot. The slice MUST NOT be mutated
// by the caller (same contract as every secrets.Source).
func (s *Source) Snapshot(_ context.Context) ([]secrets.Secret, error) {
	return s.snapshot, nil
}
