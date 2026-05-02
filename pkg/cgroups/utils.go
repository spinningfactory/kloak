package cgroups

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DefaultCgroupRoot is the standard cgroup v2 root
const DefaultCgroupRoot = "/sys/fs/cgroup"

// FindContainerCgroupPath attempts to find the cgroup path for a container ID.
// Tries well-known patterns first, then falls back to walking the cgroup tree.
func FindContainerCgroupPath(cgroupRoot, podUID, containerID string) (string, error) {
	if cgroupRoot == "" {
		cgroupRoot = DefaultCgroupRoot
	}

	podUIDUnderscored := strings.ReplaceAll(podUID, "-", "_")

	patterns := []string{
		// containerd systemd cgroup driver (standard Kubernetes)
		filepath.Join(cgroupRoot, "kubepods.slice", "kubepods-burstable.slice",
			fmt.Sprintf("kubepods-burstable-pod%s.slice", podUIDUnderscored),
			fmt.Sprintf("cri-containerd-%s.scope", containerID)),
		filepath.Join(cgroupRoot, "kubepods.slice", "kubepods-besteffort.slice",
			fmt.Sprintf("kubepods-besteffort-pod%s.slice", podUIDUnderscored),
			fmt.Sprintf("cri-containerd-%s.scope", containerID)),
		filepath.Join(cgroupRoot, "kubepods.slice", "kubepods-guaranteed.slice",
			fmt.Sprintf("kubepods-guaranteed-pod%s.slice", podUIDUnderscored),
			fmt.Sprintf("cri-containerd-%s.scope", containerID)),
		// containerd cgroupfs driver (k3s default)
		filepath.Join(cgroupRoot, "kubepods", "burstable",
			fmt.Sprintf("pod%s", podUID), containerID),
		filepath.Join(cgroupRoot, "kubepods", "besteffort",
			fmt.Sprintf("pod%s", podUID), containerID),
		filepath.Join(cgroupRoot, "kubepods", "guaranteed",
			fmt.Sprintf("pod%s", podUID), containerID),
		// containerd cgroupfs driver — Guaranteed QoS pods sit directly under
		// kubepods/pod<UID>/ with no QoS subdirectory (Talos, kubeadm cgroupfs).
		filepath.Join(cgroupRoot, "kubepods", "pod"+podUID, containerID),
		// pod-level fallback (last resort — returns pod cgroup, not container cgroup)
		filepath.Join(cgroupRoot, "kubepods", "pod"+podUID),
	}

	for _, path := range patterns {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	// Fallback: walk the cgroup tree looking for a directory containing the
	// container ID. Handles non-standard layouts (k3d, minikube, etc.).
	var found string
	_ = filepath.WalkDir(cgroupRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if strings.Contains(d.Name(), containerID) {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	if found != "" {
		return found, nil
	}

	return "", fmt.Errorf("cgroup path not found for container %s", containerID)
}

// ReadCgroupProcs reads the PIDs from a cgroup's cgroup.procs file.
func ReadCgroupProcs(cgroupPath string) ([]int, error) {
	procsPath := filepath.Join(cgroupPath, "cgroup.procs")
	data, err := os.ReadFile(procsPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", procsPath, err)
	}

	var pids []int
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pid, err := strconv.Atoi(line)
		if err != nil {
			continue
		}
		pids = append(pids, pid)
	}
	return pids, nil
}
