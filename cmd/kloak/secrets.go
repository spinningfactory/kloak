package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spinningfactory/kloak/pkg/secrets"
	yamlsrc "github.com/spinningfactory/kloak/pkg/secrets/yaml"
)

// openSecretsSource is the format dispatcher every subcommand that
// loads a secrets file should call. The plan keeps the seam clean by
// putting format selection here (CLI-layer) rather than in pkg/secrets/
// (which would force the base package to import every adapter).
//
// Today only YAML is supported; future formats add a case + an import:
//
//	case ".env":  return dotenvsrc.NewSource(path)
//	case "":      return hostenvsrc.NewSource(path /* prefix */)
//
// Anything else returns an explicit error so a typo in the file
// extension fails loudly rather than picking a wrong format silently.
func openSecretsSource(path string) (secrets.Source, error) {
	switch ext := strings.ToLower(filepath.Ext(path)); ext {
	case ".yaml", ".yml":
		return yamlsrc.NewSource(path)
	default:
		return nil, fmt.Errorf("unsupported secrets file extension %q (supported: .yaml, .yml)", ext)
	}
}
