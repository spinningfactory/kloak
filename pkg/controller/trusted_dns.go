package controller

import (
	"context"
	"net"
	"slices"
	"strings"
	"sync"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// The cluster DNS Service, whose answers the data plane trusts.
const (
	KubeDNSNamespace = "kube-system"
	KubeDNSName      = "kube-dns"
)

// TrustedDNSServers returns the DNS servers whose answers the data plane
// believes: kube-dns's ClusterIPs (both of a dual-stack Service, which pods
// are given both of as nameservers), the addresses of its endpoints, and
// static (--trusted-dns-servers). The endpoints are where answers come from
// when the CNI load balances Services at the socket (Cilium's kube-proxy
// replacement): the pod's query goes to a CoreDNS pod directly, and so the
// answer comes back from its address, not from the ClusterIP. A failed read
// leaves its addresses out.
func TrustedDNSServers(ctx context.Context, reader client.Reader, static []net.IP, log *zap.SugaredLogger) []net.IP {
	seen := make(map[string]bool)
	var out []net.IP
	add := func(s string) {
		ip := net.ParseIP(s)
		if ip == nil || seen[ip.String()] { // "None" (headless), a duplicate
			return
		}
		seen[ip.String()] = true
		out = append(out, ip)
	}

	svc := &corev1.Service{}
	if err := reader.Get(ctx, types.NamespacedName{Namespace: KubeDNSNamespace, Name: KubeDNSName}, svc); err != nil {
		log.Errorw("failed to read the kube-dns Service for the trusted DNS servers", "error", err)
	} else {
		ips := svc.Spec.ClusterIPs
		if len(ips) == 0 {
			ips = []string{svc.Spec.ClusterIP}
		}
		for _, s := range ips {
			add(s)
		}
	}

	var eps discoveryv1.EndpointSliceList
	if err := reader.List(ctx, &eps, client.InNamespace(KubeDNSNamespace),
		client.MatchingLabels{discoveryv1.LabelServiceName: KubeDNSName}); err != nil {
		log.Errorw("failed to list the kube-dns endpoints for the trusted DNS servers", "error", err)
	} else {
		for i := range eps.Items {
			if eps.Items[i].AddressType == discoveryv1.AddressTypeFQDN {
				continue
			}
			for _, ep := range eps.Items[i].Endpoints {
				for _, s := range ep.Addresses {
					add(s)
				}
			}
		}
	}

	for _, ip := range static {
		add(ip.String())
	}
	return out
}

// TrustedDNSReconciler keeps the trusted DNS servers (TrustedDNSServers) in
// the data plane as kube-dns changes: its endpoints come and go with the
// CoreDNS pods.
type TrustedDNSReconciler struct {
	client.Client
	// Static are the --trusted-dns-servers.
	Static []net.IP
	// Apply makes the data plane trust exactly these servers.
	Apply func([]net.IP) error
	Log   *zap.SugaredLogger

	mu   sync.Mutex
	last string // the servers last applied
}

// Reconcile recomputes the trusted servers and applies them when they
// changed. Every request names kube-dns.
func (r *TrustedDNSReconciler) Reconcile(ctx context.Context, _ ctrl.Request) (ctrl.Result, error) {
	ips := TrustedDNSServers(ctx, r.Client, r.Static, r.Log)
	names := make([]string, len(ips))
	for i, ip := range ips {
		names[i] = ip.String()
	}
	slices.Sort(names)
	key := strings.Join(names, ",")

	r.mu.Lock()
	defer r.mu.Unlock()
	if key == r.last {
		return ctrl.Result{}, nil
	}
	if err := r.Apply(ips); err != nil {
		return ctrl.Result{}, err
	}
	r.last = key
	r.Log.Infow("trusted DNS servers", "servers", names)
	return ctrl.Result{}, nil
}

// SetupWithManager watches the kube-dns Service and its EndpointSlices.
func (r *TrustedDNSReconciler) SetupWithManager(mgr ctrl.Manager) error {
	kubeDNS := []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: KubeDNSNamespace, Name: KubeDNSName}}}
	return ctrl.NewControllerManagedBy(mgr).
		Named("trusted-dns").
		For(&corev1.Service{}, builder.WithPredicates(predicate.NewPredicateFuncs(func(o client.Object) bool {
			return o.GetNamespace() == KubeDNSNamespace && o.GetName() == KubeDNSName
		}))).
		Watches(&discoveryv1.EndpointSlice{}, handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
			if o.GetNamespace() != KubeDNSNamespace || o.GetLabels()[discoveryv1.LabelServiceName] != KubeDNSName {
				return nil
			}
			return kubeDNS
		})).
		Complete(r)
}
