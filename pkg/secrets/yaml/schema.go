// Package yaml is one concrete `secrets.Source` implementation: it
// reads a kloak-native YAML file and emits the canonical
// `[]secrets.Secret` slice the data plane consumes.
//
// The package owns three layers in strict separation, so adding another
// on-disk format (`.env`, host env vars, …) is a copy of this package
// with the schema struct swapped — no other code path moves:
//
//	schema.go    private types tagged for yaml.v3; the only thing that
//	             knows about the on-disk shape.
//	translate.go pure schema → []secrets.Secret + validation; no I/O.
//	source.go    secrets.Source adapter; loads + translates at New, caches
//	             the snapshot.
//
// Future format packages mirror the layout. The public seam is
// pkg/secrets.{Secret, Source, ShadowGenerator, ParseHost, ParsePort} —
// not the schema struct.
package yaml

// fileSpec is the top-level on-disk shape. yaml.v3 unmarshals into this
// struct; nothing outside this package depends on it. Field names match
// the user-facing YAML keys, not the internal model.
type fileSpec struct {
	Secrets []secretSpec `yaml:"secrets"`
}

// secretSpec is one entry under the `secrets:` list. All fields except
// Name and Inject are optional at the schema level; the translator
// enforces the semantic rules (exactly one of Value / ValueFrom, at
// least one Inject target, etc.).
type secretSpec struct {
	Name      string         `yaml:"name"`
	Value     string         `yaml:"value,omitempty"`
	ValueFrom *valueFromSpec `yaml:"valueFrom,omitempty"`
	Host      string         `yaml:"host,omitempty"`
	// Port is a string at the schema layer so we can accept both bare
	// numbers ("443") and the "<port>/<proto>" form ("443/tcp"). The
	// translator splits it via pkg/secrets.ParsePort.
	Port   string     `yaml:"port,omitempty"`
	Inject injectSpec `yaml:"inject"`
}

// valueFromSpec lets `secrets.yaml` reference a real value indirectly so
// the file itself stays safe to commit. Env is the only source for now;
// future backends (op://, aws-sm://, …) get sibling fields here.
type valueFromSpec struct {
	Env string `yaml:"env,omitempty"`
}

// injectSpec is the per-secret request for how the shadow value should
// be exposed to the child process the `kloak run` runtime spawns. Both
// fields may be set on the same secret (env AND file), but at least one
// must be — a secret with no injection target has no way to reach the
// child and is rejected at translate time.
type injectSpec struct {
	Env  string `yaml:"env,omitempty"`
	File string `yaml:"file,omitempty"`
}
