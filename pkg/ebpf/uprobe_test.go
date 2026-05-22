//go:build linux

package ebpf

import (
	"fmt"
	"os"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
)

func TestIsTLSLibrary(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		// OpenSSL
		{"libssl.so", true},
		{"libssl.so.3", true},
		{"libssl.so.1.1", true},
		// BoringSSL
		{"libboringssl.so", true},
		{"libboringssl.so.1", true},
		// libcrypto
		{"libcrypto.so", true},
		{"libcrypto.so.3", true},
		// GnuTLS
		{"libgnutls.so", true},
		{"libgnutls.so.30", true},
		{"libgnutls.so.30.34.2", true},
		// Non-TLS libraries
		{"libc.so.6", false},
		{"libpthread.so.0", false},
		{"libssl-extra.so", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTLSLibrary(tt.name); got != tt.want {
				t.Errorf("isTLSLibrary(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestParseBPFLogLevel(t *testing.T) {
	tests := []struct {
		input string
		want  ebpf.LogLevel
	}{
		{"", 0},
		{"off", 0},
		{"OFF", 0},
		{"disabled", 0},
		{"none", 0},
		{"branch", ebpf.LogLevelBranch},
		{"BRANCH", ebpf.LogLevelBranch},
		{"  branch  ", ebpf.LogLevelBranch},
		{"instruction", ebpf.LogLevelInstruction},
		{"instructions", ebpf.LogLevelInstruction},
		{"stats", ebpf.LogLevelStats},
		{"branch,stats", ebpf.LogLevelBranch | ebpf.LogLevelStats},
		{"branch, stats", ebpf.LogLevelBranch | ebpf.LogLevelStats},
		{"unknown", 0},
		{"branch,unknown", ebpf.LogLevelBranch},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := parseBPFLogLevel(tt.input); got != tt.want {
				t.Errorf("parseBPFLogLevel(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseDefaultRouteInterface(t *testing.T) {
	// parseDefaultRouteInterface is the pure-bytes half of
	// findDefaultRouteInterface — exercising it directly avoids
	// reading the live kernel's /proc/net/route in tests. The cases
	// cover the realistic shapes the parser sees in the field:
	// CNI-managed pod netns with "eth0", host-mode netns with
	// arbitrary udev-assigned names, netns with no default route at
	// all (mid-CNI-setup), and degenerate/empty inputs.
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "default via eth0 (CNI pod netns)",
			body: "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
				"eth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" +
				"eth0\t000011AC\t00000000\t0001\t0\t0\t0\tFFFFFFFF\t0\t0\t0\n",
			want: "eth0",
		},
		{
			name: "default via wlp3s0 (Fedora-style host name)",
			body: "Iface\tDestination\tGateway\tFlags\n" +
				"wlp3s0\t00000000\t0101A8C0\t0003\n",
			want: "wlp3s0",
		},
		{
			name: "default via enp0s3 (systemd-style host name)",
			body: "Iface\tDestination\tGateway\tFlags\n" +
				"enp0s3\t00000000\t02000A0A\t0003\n",
			want: "enp0s3",
		},
		{
			name: "no default route — only specifics",
			body: "Iface\tDestination\tGateway\tFlags\n" +
				"eth0\t000011AC\t00000000\t0001\n" +
				"lo\t0000007F\t00000000\t0001\n",
			want: "",
		},
		{
			name: "empty file (header only)",
			body: "Iface\tDestination\tGateway\tFlags\n",
			want: "",
		},
		{
			name: "completely empty",
			body: "",
			want: "",
		},
		{
			name: "garbled line is skipped, default still found below",
			body: "Iface\tDestination\tGateway\tFlags\n" +
				"oneword\n" +
				"eth0\t00000000\t0101A8C0\t0003\n",
			want: "eth0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseDefaultRouteInterface([]byte(tc.body)); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWalkTLSLibrariesUnder_Recursive(t *testing.T) {
	// walkTLSLibrariesUnder is the recursive scan that backs
	// findContainerTLSLibraries; exercising it against a synthetic
	// filesystem laid out under a tmpdir pins the "finds libs at any
	// depth under the configured roots" contract. This regressed on
	// Fedora when only one-level descent + a Debian-centric root list
	// shipped: Fedora's /usr/lib64/libssl.so.3 fell outside both the
	// roots AND the depth limit.
	tmpRoot := t.TempDir()
	mustMkdir := func(p string) {
		t.Helper()
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", p, err)
		}
	}
	mustTouch := func(p string) {
		t.Helper()
		if err := os.WriteFile(p, []byte("fake"), 0o644); err != nil {
			t.Fatalf("touch %s: %v", p, err)
		}
	}

	// Realistic cross-distro filesystem layout under tmpRoot:
	//   /usr/lib/x86_64-linux-gnu/libssl.so.3      (Debian/Ubuntu)
	//   /usr/lib64/libssl.so.3                     (Fedora/RHEL)
	//   /usr/lib/libcrypto.so.3                    (Alpine/Arch top-level)
	//   /usr/lib64/libgnutls.so.30                 (Fedora GnuTLS)
	//   /lib/x86_64-linux-gnu/sub/deep/libssl.so   (depth stress test)
	//   /lib64/libssl.so                           (Fedora legacy)
	//   /usr/local/lib/custom/libssl.so            (admin-installed)
	//   /etc/ssl/libssl.so                         (NOT under any
	//                                               scanned root → must
	//                                               NOT be found)
	mustMkdir(tmpRoot + "/usr/lib/x86_64-linux-gnu")
	mustTouch(tmpRoot + "/usr/lib/x86_64-linux-gnu/libssl.so.3")
	mustMkdir(tmpRoot + "/usr/lib64")
	mustTouch(tmpRoot + "/usr/lib64/libssl.so.3")
	mustTouch(tmpRoot + "/usr/lib/libcrypto.so.3")
	mustTouch(tmpRoot + "/usr/lib64/libgnutls.so.30")
	mustMkdir(tmpRoot + "/lib/x86_64-linux-gnu/sub/deep")
	mustTouch(tmpRoot + "/lib/x86_64-linux-gnu/sub/deep/libssl.so")
	mustMkdir(tmpRoot + "/lib64")
	mustTouch(tmpRoot + "/lib64/libssl.so")
	mustMkdir(tmpRoot + "/usr/local/lib/custom")
	mustTouch(tmpRoot + "/usr/local/lib/custom/libssl.so")
	mustMkdir(tmpRoot + "/etc/ssl")
	mustTouch(tmpRoot + "/etc/ssl/libssl.so")

	// Negative: non-TLS .so under a scanned root.
	mustTouch(tmpRoot + "/usr/lib/libfoo.so")

	got := walkTLSLibrariesUnder(tmpRoot)
	gotSet := make(map[string]bool, len(got))
	for _, p := range got {
		gotSet[p] = true
	}

	want := []string{
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib64/libssl.so.3",
		"/usr/lib/libcrypto.so.3",
		"/usr/lib64/libgnutls.so.30",
		"/lib/x86_64-linux-gnu/sub/deep/libssl.so",
		"/lib64/libssl.so",
		"/usr/local/lib/custom/libssl.so",
	}
	for _, w := range want {
		if !gotSet[w] {
			t.Errorf("missing expected TLS library %q (got=%v)", w, got)
		}
	}
	for _, banned := range []string{
		"/etc/ssl/libssl.so", // outside scanned roots
		"/usr/lib/libfoo.so", // not a TLS lib name
	} {
		if gotSet[banned] {
			t.Errorf("scanner picked up %q which should NOT be found", banned)
		}
	}
}

func TestWalkTLSLibrariesUnder_DeduplicatesByInode(t *testing.T) {
	// Two flavors of duplicate that the path-string dedup missed and
	// inode-dedup catches:
	//
	//   1. UsrMove: /lib is a symlink to /usr/lib (Fedora, Arch, modern
	//      Debian). WalkDir follows the root if it IS a symlink, so the
	//      same files appear once under /usr/lib/... and once under
	//      /lib/... — different path strings, same inode.
	//   2. Library aliases inside one directory: libssl.so → libssl.so.3
	//      is a symlink that WalkDir does NOT follow (it's not a root),
	//      so both DirEntries are visited. Same inode, both pass
	//      isTLSLibrary.
	//
	// Attaching uprobes to the same inode twice wastes a verifier slot
	// and produces duplicate ringbuf events. This test pins the
	// invariant that walkTLSLibrariesUnder returns each physical file
	// once.
	tmpRoot := t.TempDir()
	mustMkdir := func(p string) {
		t.Helper()
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", p, err)
		}
	}
	mustTouch := func(p string) {
		t.Helper()
		if err := os.WriteFile(p, []byte("fake"), 0o644); err != nil {
			t.Fatalf("touch %s: %v", p, err)
		}
	}
	mustSymlink := func(target, link string) {
		t.Helper()
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("symlink %s → %s: %v", link, target, err)
		}
	}

	// Case 1: UsrMove — /lib symlinks to /usr/lib.
	mustMkdir(tmpRoot + "/usr/lib")
	mustTouch(tmpRoot + "/usr/lib/libssl.so.3")
	// Relative symlink from tmpRoot/lib → tmpRoot/usr/lib so the
	// in-tree layout mirrors what a real Fedora root_fs looks like.
	mustSymlink("usr/lib", tmpRoot+"/lib")

	// Case 2: alias inside one directory — libssl.so → libssl.so.3.
	// /usr/lib64 stays a real directory; libssl.so is a symlink
	// pointing at libssl.so.3 inside the same directory.
	mustMkdir(tmpRoot + "/usr/lib64")
	mustTouch(tmpRoot + "/usr/lib64/libssl.so.3")
	mustSymlink("libssl.so.3", tmpRoot+"/usr/lib64/libssl.so")

	got := walkTLSLibrariesUnder(tmpRoot)

	// Each physical inode appears at most once. We don't pin which
	// path string wins (walk order can pick either) — the contract is
	// "no two entries share an inode."
	seen := make(map[string]int)
	for _, p := range got {
		info, err := os.Stat(tmpRoot + p)
		if err != nil {
			t.Fatalf("stat %s: %v", tmpRoot+p, err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Fatalf("non-Stat_t Sys() on %s", p)
		}
		key := fmt.Sprintf("%d:%d", stat.Dev, stat.Ino)
		seen[key]++
	}
	for inodeKey, count := range seen {
		if count > 1 {
			t.Errorf("inode %s appears %d times in scan result; expected 1\nfull result: %v", inodeKey, count, got)
		}
	}

	// And we still find SOMETHING for each physical lib — the dedup
	// must not be so aggressive that it drops everything.
	if len(got) < 2 {
		t.Errorf("expected at least 2 distinct TLS libs (UsrMove file + alias target), got %d: %v", len(got), got)
	}
}
