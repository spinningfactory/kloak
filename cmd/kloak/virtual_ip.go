package main

import (
	"context"
	"fmt"
	"net/netip"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/spinningfactory/kloak/pkg/ebpf"
)

// checkVirtualIPRange refuses a virtual IP range that overlaps an address
// range in use on the cluster or the node (see discoverReservedRanges).
func checkVirtualIPRange(ctx context.Context, reader client.Reader, r netip.Prefix, procDir string, log *zap.SugaredLogger) error {
	reserved, err := discoverReservedRanges(ctx, reader, procDir, log)
	if err != nil {
		return fmt.Errorf("listing the address ranges in use: %w", err)
	}
	if err := ebpf.CheckVirtualIPRange(r, reserved); err != nil {
		return err
	}
	log.Infow("virtual IP range does not overlap any address range in use",
		"range", r.String(), "checkedRanges", len(reserved))
	return nil
}

// discoverReservedRanges lists the address ranges the virtual IP range must
// not overlap: the pod CIDRs and addresses of every node, the service CIDRs,
// and the routes of the node this controller runs on (procDir is the procfs
// directory of a process in the host network namespace, such as "/proc/1"
// with hostPID). Node routes also cover pod ranges a CNI assigns without
// Node.spec.podCIDRs (Cilium cluster-pool or Calico IPAM), at least those
// routed through this node.
func discoverReservedRanges(ctx context.Context, reader client.Reader, procDir string, log *zap.SugaredLogger) ([]ebpf.ReservedRange, error) {
	var reserved []ebpf.ReservedRange

	var nodes corev1.NodeList
	if err := reader.List(ctx, &nodes); err != nil {
		return nil, fmt.Errorf("listing nodes: %w", err)
	}
	podCIDRs := 0
	for i := range nodes.Items {
		n := &nodes.Items[i]
		cidrs := n.Spec.PodCIDRs
		if len(cidrs) == 0 && n.Spec.PodCIDR != "" {
			cidrs = []string{n.Spec.PodCIDR}
		}
		for _, c := range cidrs {
			p, err := netip.ParsePrefix(c)
			if err != nil {
				log.Warnw("ignoring unparsable node pod CIDR", "node", n.Name, "cidr", c, "error", err)
				continue
			}
			reserved = append(reserved, ebpf.ReservedRange{Prefix: p.Masked(), Source: "pod CIDR of node " + n.Name})
			podCIDRs++
		}
		for _, a := range n.Status.Addresses {
			if a.Type != corev1.NodeInternalIP && a.Type != corev1.NodeExternalIP {
				continue
			}
			if r, ok := hostRange(a.Address, "address of node "+n.Name); ok {
				reserved = append(reserved, r)
			}
		}
	}
	if podCIDRs == 0 {
		log.Warnw("no node has spec.podCIDRs set (the CNI assigns pod IPs itself): only node routes cover pod ranges in the virtual IP range check")
	}

	var serviceCIDRs networkingv1.ServiceCIDRList
	err := reader.List(ctx, &serviceCIDRs)
	switch {
	case err == nil:
		for i := range serviceCIDRs.Items {
			sc := &serviceCIDRs.Items[i]
			for _, c := range sc.Spec.CIDRs {
				p, err := netip.ParsePrefix(c)
				if err != nil {
					log.Warnw("ignoring unparsable service CIDR", "serviceCIDR", sc.Name, "cidr", c, "error", err)
					continue
				}
				reserved = append(reserved, ebpf.ReservedRange{Prefix: p.Masked(), Source: "service CIDR " + sc.Name})
			}
		}
	case meta.IsNoMatchError(err) || apierrors.IsNotFound(err):
		// ServiceCIDR is GA from Kubernetes 1.33. Before that the service
		// range is only known to the API server's flags.
		log.Warnw("ServiceCIDR API not available: checking the ClusterIPs of kubernetes and kube-dns instead of the service range")
		for _, nn := range []types.NamespacedName{
			{Namespace: "default", Name: "kubernetes"},
			{Namespace: "kube-system", Name: "kube-dns"},
		} {
			var svc corev1.Service
			if err := reader.Get(ctx, nn, &svc); err != nil {
				log.Warnw("could not read service for the virtual IP range check", "service", nn.String(), "error", err)
				continue
			}
			for _, ip := range svc.Spec.ClusterIPs {
				if r, ok := hostRange(ip, "ClusterIP of service "+nn.String()); ok {
					reserved = append(reserved, r)
				}
			}
		}
	default:
		return nil, fmt.Errorf("listing service CIDRs: %w", err)
	}

	routes, err := ebpf.HostRoutes(procDir)
	if err != nil {
		return nil, err
	}
	return append(reserved, routes...), nil
}

// hostRange returns a single-address range for ip.
func hostRange(ip, source string) (ebpf.ReservedRange, bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ebpf.ReservedRange{}, false
	}
	a = a.Unmap()
	return ebpf.ReservedRange{Prefix: netip.PrefixFrom(a, a.BitLen()), Source: source}, true
}
