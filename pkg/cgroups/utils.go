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

// FindContainerCgroupPath attempts to find the cgroup path for a container ID
func FindContainerCgroupPath(cgroupRoot, podUID, containerID string) (string, error) {
	if cgroupRoot == "" {
		cgroupRoot = DefaultCgroupRoot
	}

	podUIDUnderscored := strings.ReplaceAll(podUID, "-", "_")

	patterns := []string{
		// containerd pattern
		filepath.Join(cgroupRoot, "kubepods.slice", "kubepods-burstable.slice",
			fmt.Sprintf("kubepods-burstable-pod%s.slice", podUIDUnderscored),
			fmt.Sprintf("cri-containerd-%s.scope", containerID)),
		// containerd pattern (BestEffort)
		filepath.Join(cgroupRoot, "kubepods.slice", "kubepods-besteffort.slice",
			fmt.Sprintf("kubepods-besteffort-pod%s.slice", podUIDUnderscored),
			fmt.Sprintf("cri-containerd-%s.scope", containerID)),
		// Alternative pattern
		filepath.Join(cgroupRoot, "kubepods", "burstable",
			fmt.Sprintf("pod%s", podUID), containerID),
		// Best-effort pattern
		filepath.Join(cgroupRoot, "kubepods", "pod"+podUID),
	}

	for _, path := range patterns {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("cgroup path not found for container %s", containerID)
}

// GetPodCgroupPath returns the parent cgroup of a container, which corresponds to the Pod cgroup.
// It uses FindContainerCgroupPath to locate the container first, and falls back to
// searching for the pod-level cgroup slice directly if the container scope is not yet created.
func GetPodCgroupPath(cgroupRoot, podUID, containerID string) (string, error) {
	if cgroupRoot == "" {
		cgroupRoot = DefaultCgroupRoot
	}

	podUIDUnderscored := strings.ReplaceAll(podUID, "-", "_")

	// 1. Try finding container first (to get the exact slice)
	if containerPath, err := FindContainerCgroupPath(cgroupRoot, podUID, containerID); err == nil {
		return filepath.Dir(containerPath), nil
	}

	// 2. Fallback: Search for Pod-level cgroup slice directly (common when container scope isn't ready)
	podPatterns := []string{
		// containerd/systemd patterns
		filepath.Join(cgroupRoot, "kubepods.slice", "kubepods-burstable.slice",
			fmt.Sprintf("kubepods-burstable-pod%s.slice", podUIDUnderscored)),
		filepath.Join(cgroupRoot, "kubepods.slice", "kubepods-besteffort.slice",
			fmt.Sprintf("kubepods-besteffort-pod%s.slice", podUIDUnderscored)),
		filepath.Join(cgroupRoot, "kubepods.slice",
			fmt.Sprintf("kubepods-pod%s.slice", podUIDUnderscored)),
		// Alternative patterns
		filepath.Join(cgroupRoot, "kubepods", "burstable", fmt.Sprintf("pod%s", podUID)),
		filepath.Join(cgroupRoot, "kubepods", "pod"+podUID),
	}

	for _, path := range podPatterns {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("pod cgroup path not found for pod %s", podUID)
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
