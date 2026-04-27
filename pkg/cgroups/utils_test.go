package cgroups

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// mkdirAll creates the directory tree, failing the test on error.
func mkdirAll(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", p, err)
		}
	}
}

func TestFindContainerCgroupPath_DefaultsToStandardRoot(t *testing.T) {
	// We can't actually exercise DefaultCgroupRoot on a non-Linux test runner,
	// but we can verify FindContainerCgroupPath returns an error rather than
	// panicking when an empty cgroupRoot is passed (it falls back to
	// DefaultCgroupRoot which won't contain our fake container).
	got, err := FindContainerCgroupPath("", "ffffffff-ffff-ffff-ffff-ffffffffffff", "no-such-container")
	if err == nil {
		t.Fatalf("expected error for unknown container, got %q", got)
	}
}

func TestFindContainerCgroupPath_ContainerdSystemdLayouts(t *testing.T) {
	const podUID = "abcd1234-5678-9abc-def0-fedcba987654"
	const containerID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	podUnderscored := strings.ReplaceAll(podUID, "-", "_")

	cases := []struct {
		name      string
		qos       string
		layoutFmt string // %s = qos
	}{
		{"burstable", "burstable", "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod%s.slice/cri-containerd-%s.scope"},
		{"besteffort", "besteffort", "kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod%s.slice/cri-containerd-%s.scope"},
		{"guaranteed", "guaranteed", "kubepods.slice/kubepods-guaranteed.slice/kubepods-guaranteed-pod%s.slice/cri-containerd-%s.scope"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			// e.g. kubepods-burstable-pod<UID_with_underscores>.slice/cri-containerd-<CID>.scope
			rel := strings.NewReplacer(
				"%s/", podUnderscored+"/", // pod placeholder (first %s)
			).Replace(tc.layoutFmt)
			// Re-do the substitution properly via fmt.Sprintf-style.
			// Easier: assemble manually.
			var subdir string
			switch tc.qos {
			case "burstable":
				subdir = filepath.Join("kubepods.slice", "kubepods-burstable.slice",
					"kubepods-burstable-pod"+podUnderscored+".slice",
					"cri-containerd-"+containerID+".scope")
			case "besteffort":
				subdir = filepath.Join("kubepods.slice", "kubepods-besteffort.slice",
					"kubepods-besteffort-pod"+podUnderscored+".slice",
					"cri-containerd-"+containerID+".scope")
			case "guaranteed":
				subdir = filepath.Join("kubepods.slice", "kubepods-guaranteed.slice",
					"kubepods-guaranteed-pod"+podUnderscored+".slice",
					"cri-containerd-"+containerID+".scope")
			}
			_ = rel
			full := filepath.Join(root, subdir)
			mkdirAll(t, full)

			got, err := FindContainerCgroupPath(root, podUID, containerID)
			if err != nil {
				t.Fatalf("FindContainerCgroupPath: %v", err)
			}
			if got != full {
				t.Errorf("got  %q\nwant %q", got, full)
			}
		})
	}
}

func TestFindContainerCgroupPath_CgroupfsLayout(t *testing.T) {
	// k3s default driver uses /kubepods/<qos>/pod<UID>/<CID> with raw UID (no
	// underscores) and no .scope suffix.
	const podUID = "abcd1234-5678-9abc-def0-fedcba987654"
	const containerID = "deadbeefdeadbeef"

	for _, qos := range []string{"burstable", "besteffort", "guaranteed"} {
		t.Run(qos, func(t *testing.T) {
			root := t.TempDir()
			full := filepath.Join(root, "kubepods", qos, "pod"+podUID, containerID)
			mkdirAll(t, full)

			got, err := FindContainerCgroupPath(root, podUID, containerID)
			if err != nil {
				t.Fatalf("FindContainerCgroupPath: %v", err)
			}
			if got != full {
				t.Errorf("got  %q\nwant %q", got, full)
			}
		})
	}
}

func TestFindContainerCgroupPath_PodLevelFallback(t *testing.T) {
	const podUID = "11111111-2222-3333-4444-555555555555"
	const containerID = "any-cid"

	root := t.TempDir()
	full := filepath.Join(root, "kubepods", "pod"+podUID)
	mkdirAll(t, full)

	got, err := FindContainerCgroupPath(root, podUID, containerID)
	if err != nil {
		t.Fatalf("FindContainerCgroupPath: %v", err)
	}
	if got != full {
		t.Errorf("got  %q\nwant %q", got, full)
	}
}

func TestFindContainerCgroupPath_TreeWalkFallback(t *testing.T) {
	// None of the patterns match — walk the tree and find any dir whose name
	// contains the container ID. Models k3d / minikube layouts.
	const podUID = "99999999-9999-9999-9999-999999999999"
	const containerID = "uniquecontainerid42"

	root := t.TempDir()
	odd := filepath.Join(root, "weird", "layout", "containerd-"+containerID+"-foo")
	mkdirAll(t, odd)

	got, err := FindContainerCgroupPath(root, podUID, containerID)
	if err != nil {
		t.Fatalf("FindContainerCgroupPath: %v", err)
	}
	if got != odd {
		t.Errorf("got  %q\nwant %q", got, odd)
	}
}

func TestFindContainerCgroupPath_NotFound(t *testing.T) {
	root := t.TempDir()
	// Empty root: no patterns match, walk finds nothing.
	got, err := FindContainerCgroupPath(root, "deadbeef", "missing-cid")
	if err == nil {
		t.Fatalf("expected error, got path %q", got)
	}
	if !strings.Contains(err.Error(), "missing-cid") {
		t.Errorf("error should mention container id, got: %v", err)
	}
}

func TestReadCgroupProcs(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    []int
	}{
		{"empty", "", nil},
		{"single pid", "12345\n", []int{12345}},
		{"multiple pids", "1\n2\n3\n", []int{1, 2, 3}},
		// Real cgroup.procs files have a trailing newline; the function trims
		// whitespace before splitting.
		{"trailing whitespace", "  100\n200  \n", []int{100, 200}},
		// Blank lines and garbage entries are dropped.
		{"blank line tolerated", "10\n\n20\n", []int{10, 20}},
		{"garbage skipped", "100\nnot-a-pid\n200\n", []int{100, 200}},
		{"only garbage", "abc\n.\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cgPath := t.TempDir()
			if err := os.WriteFile(filepath.Join(cgPath, "cgroup.procs"), []byte(tc.content), 0o644); err != nil {
				t.Fatalf("write file: %v", err)
			}
			got, err := ReadCgroupProcs(cgPath)
			if err != nil {
				t.Fatalf("ReadCgroupProcs: %v", err)
			}
			sort.Ints(got)
			sort.Ints(tc.want)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestReadCgroupProcs_MissingFile(t *testing.T) {
	root := t.TempDir()
	// Don't create cgroup.procs.
	_, err := ReadCgroupProcs(root)
	if err == nil {
		t.Fatal("expected error reading non-existent cgroup.procs")
	}
	if !strings.Contains(err.Error(), "cgroup.procs") {
		t.Errorf("error should mention the file, got: %v", err)
	}
}
