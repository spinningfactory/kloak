package main

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// version is the release tag for shipped builds, set at build time via:
//
//	-ldflags "-X main.version=v0.1.0"
//
// Dev builds without that flag fall back to "dev"; the commit hash that
// versionString reports below comes from runtime/debug.ReadBuildInfo, so
// the dev fallback still pins the source tree exactly.
var version = "dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print kloak version, commit hash, and Go runtime",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Print(versionString())
	},
}

func versionString() string {
	commit, dirty, goVer := buildInfo()
	tree := "clean"
	if dirty {
		tree = "dirty"
	}
	return fmt.Sprintf("kloak version %s\ncommit:        %s (%s)\ngo:            %s\n",
		version, commit, tree, goVer)
}

// buildInfo extracts the VCS revision, dirty flag, and Go toolchain
// version from the binary's embedded build info. Go ≥1.18 records these
// automatically when building from a checkout under VCS, so no
// `--build-arg GIT_COMMIT=…` plumbing is needed in the Dockerfile.
func buildInfo() (commit string, dirty bool, goVer string) {
	commit = "unknown"
	goVer = "unknown"
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	goVer = info.GoVersion
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if len(s.Value) >= 7 {
				commit = s.Value[:7]
			} else {
				commit = s.Value
			}
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	return
}
