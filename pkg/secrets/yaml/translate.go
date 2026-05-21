package yaml

import (
	"errors"
	"fmt"
	"os"

	"github.com/spinningfactory/kloak/pkg/secrets"
)

// maxRealLen mirrors the BPF wire-format secretValue.RealSecret cap in
// pkg/ebpf/uprobe.go. Keeping this constant local (rather than reaching
// across packages) avoids dragging the Linux-only ebpf package into the
// portable secrets/yaml build; the value is part of kloak's on-disk
// contract, not a Linux-runtime detail.
const maxRealLen = 128

// translate converts a parsed fileSpec into the canonical
// []secrets.Secret slice. Pure function (apart from os.Getenv used to
// resolve `valueFrom.env`): no I/O against the source file, no clock,
// no network. The ShadowGenerator is supplied by the caller so tests
// can pass a deterministic seed.
//
// All validation lives here so the translator itself is the single
// source of truth for what a valid YAML entry looks like. The Source
// adapter (source.go) is just YAML load + Snapshot caching.
func translate(spec fileSpec, gen *secrets.ShadowGenerator) ([]secrets.Secret, error) {
	if len(spec.Secrets) == 0 {
		return nil, fmt.Errorf("secrets.yaml: no secrets defined under `secrets:`")
	}

	// Detect duplicate names early so the per-entry error messages don't
	// mention rules that pass for both copies of the same name.
	seenNames := make(map[string]int, len(spec.Secrets))
	for i, s := range spec.Secrets {
		if s.Name == "" {
			return nil, fmt.Errorf("secrets.yaml: entry %d: `name` is required", i)
		}
		if prev, dup := seenNames[s.Name]; dup {
			return nil, fmt.Errorf("secrets.yaml: duplicate secret name %q (entries %d and %d)", s.Name, prev, i)
		}
		seenNames[s.Name] = i
	}

	out := make([]secrets.Secret, 0, len(spec.Secrets))
	for i := range spec.Secrets {
		s := &spec.Secrets[i]
		realVal, err := resolveRealValue(s)
		if err != nil {
			return nil, fmt.Errorf("secrets.yaml: entry %d (%q): %w", i, s.Name, err)
		}
		if len(realVal) > maxRealLen {
			return nil, fmt.Errorf("secrets.yaml: entry %d (%q): real value is %d bytes, max is %d", i, s.Name, len(realVal), maxRealLen)
		}

		host, ip := secrets.ParseHost(s.Host)

		var port uint16
		var proto uint8
		if s.Port != "" {
			ps, err := secrets.ParsePort(s.Port)
			if err != nil {
				return nil, fmt.Errorf("secrets.yaml: entry %d (%q): invalid port %q: %w", i, s.Name, s.Port, err)
			}
			port = ps.Port
			proto = ps.Protocol
		}

		inject, err := resolveInject(s.Inject)
		if err != nil {
			return nil, fmt.Errorf("secrets.yaml: entry %d (%q): %w", i, s.Name, err)
		}

		// The shadow is minted with the secret name as the ownerID so a
		// future hot-reload of the same secret reuses its own prefix
		// instead of treating itself as a collision. maxRetries=20
		// mirrors the controller's value at pkg/controller/secret_reconciler.go.
		//
		// Pass the Huffman bit count, not the real value itself — keeps
		// the cleartext from leaving this function's scope. The bit-exact
		// length is what the shadow generator needs to construct a shadow
		// whose encoded wire bytes match the real's exactly (no HPACK
		// EOS over-padding).
		shadow, err := gen.Generate(len(realVal), secrets.HuffmanBits(realVal), s.Name, 20)
		if err != nil {
			if errors.Is(err, secrets.ErrHuffmanInvariantUnsatisfiable) {
				return nil, fmt.Errorf("secrets.yaml: entry %d (%q): cannot mint a shadow with sufficient HPACK Huffman length — the real value's encoding is too dense for the requested length (consider a longer secret value): %w", i, s.Name, err)
			}
			return nil, fmt.Errorf("secrets.yaml: entry %d (%q): shadow generation failed: %w", i, s.Name, err)
		}

		out = append(out, secrets.Secret{
			OwnerID:  s.Name,
			Key:      s.Name,
			Real:     realVal,
			Shadow:   shadow,
			Host:     host,
			IP:       ip,
			Port:     port,
			Protocol: proto,
			Inject:   inject,
		})
	}
	return out, nil
}

// resolveRealValue returns the literal value the secret rewrites to,
// reading from `valueFrom.env` if Value is empty. Exactly one of the
// two must be set, and `valueFrom.env` must resolve to a non-empty
// string — a missing env var is a configuration error, not a silent
// empty secret. Takes a pointer to avoid the hugeParam copy the linter
// flags (secretSpec is 104 bytes).
func resolveRealValue(s *secretSpec) (string, error) {
	switch {
	case s.Value != "" && s.ValueFrom != nil:
		return "", fmt.Errorf("`value` and `valueFrom` are mutually exclusive")
	case s.Value != "":
		return s.Value, nil
	case s.ValueFrom != nil:
		if s.ValueFrom.Env == "" {
			return "", fmt.Errorf("`valueFrom` requires `env` (additional backends not yet supported)")
		}
		v, ok := os.LookupEnv(s.ValueFrom.Env)
		if !ok || v == "" {
			return "", fmt.Errorf("`valueFrom.env: %s` resolves to empty / unset; refusing to ship an empty real value", s.ValueFrom.Env)
		}
		return v, nil
	default:
		return "", fmt.Errorf("must set exactly one of `value` or `valueFrom`")
	}
}

// resolveInject normalizes the injection target. At least one of
// Env / File must be set; everything else (e.g. validating that File is
// an absolute path) is enforced by the runtime that actually
// materializes the injection — keeping it out of the translator lets
// the YAML source stay loadable on macOS for tooling like
// `kloak secrets validate`.
func resolveInject(spec injectSpec) (secrets.Inject, error) {
	if spec.Env == "" && spec.File == "" {
		return secrets.Inject{}, fmt.Errorf("`inject` must set at least one of `env` or `file`")
	}
	return secrets.Inject{Env: spec.Env, File: spec.File}, nil
}
