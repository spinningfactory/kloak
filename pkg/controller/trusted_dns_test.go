package controller

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func dnsScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = discoveryv1.AddToScheme(s)
	return s
}

func kubeDNS(clusterIPs ...string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: KubeDNSNamespace, Name: KubeDNSName},
		Spec:       corev1.ServiceSpec{ClusterIP: clusterIPs[0], ClusterIPs: clusterIPs},
	}
}

func kubeDNSSlice(name string, family discoveryv1.AddressType, svc string, addrs ...string) *discoveryv1.EndpointSlice {
	es := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Namespace: KubeDNSNamespace, Name: name,
			Labels: map[string]string{discoveryv1.LabelServiceName: svc}},
		AddressType: family,
	}
	for _, a := range addrs {
		es.Endpoints = append(es.Endpoints, discoveryv1.Endpoint{Addresses: []string{a}})
	}
	return es
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	slices.Sort(out)
	return out
}

func TestTrustedDNSServers(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(dnsScheme()).WithObjects(
		kubeDNS("10.43.0.10", "fd43::a"),
		// The CoreDNS pods: answers come from them under socket load
		// balancing.
		kubeDNSSlice("kube-dns-v4", discoveryv1.AddressTypeIPv4, KubeDNSName, "10.42.0.5", "10.42.0.6"),
		kubeDNSSlice("kube-dns-v6", discoveryv1.AddressTypeIPv6, KubeDNSName, "fd42::5"),
		kubeDNSSlice("kube-dns-fqdn", discoveryv1.AddressTypeFQDN, KubeDNSName, "dns.example.com"),
		// Another Service's endpoints in kube-system.
		kubeDNSSlice("metrics", discoveryv1.AddressTypeIPv4, "metrics-server", "10.42.0.9"),
	).Build()
	static := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("10.42.0.5")}
	got := ipStrings(TrustedDNSServers(context.Background(), c, static, zap.NewNop().Sugar()))
	want := []string{"1.1.1.1", "10.42.0.5", "10.42.0.6", "10.43.0.10", "fd42::5", "fd43::a"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	// No kube-dns at all: the static servers only.
	empty := fake.NewClientBuilder().WithScheme(dnsScheme()).Build()
	if got := ipStrings(TrustedDNSServers(context.Background(), empty, static, zap.NewNop().Sugar())); !slices.Equal(got, []string{"1.1.1.1", "10.42.0.5"}) {
		t.Errorf("without kube-dns: %v", got)
	}
}

func TestTrustedDNSReconciler(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(dnsScheme()).WithObjects(
		kubeDNS("10.43.0.10"),
		kubeDNSSlice("kube-dns-v4", discoveryv1.AddressTypeIPv4, KubeDNSName, "10.42.0.5"),
	).Build()
	var applied [][]string
	fail := false
	r := &TrustedDNSReconciler{Client: c, Log: zap.NewNop().Sugar(), Apply: func(ips []net.IP) error {
		if fail {
			return errors.New("map full")
		}
		applied = append(applied, ipStrings(ips))
		return nil
	}}
	ctx := context.Background()
	reconcile := func() error {
		_, err := r.Reconcile(ctx, ctrl.Request{})
		return err
	}

	if err := reconcile(); err != nil {
		t.Fatal(err)
	}
	if err := reconcile(); err != nil { // nothing changed
		t.Fatal(err)
	}
	if len(applied) != 1 || !slices.Equal(applied[0], []string{"10.42.0.5", "10.43.0.10"}) {
		t.Fatalf("applied %v", applied)
	}

	// CoreDNS is replaced: a new endpoint address.
	es := &discoveryv1.EndpointSlice{}
	if err := c.Get(ctx, client.ObjectKey{Namespace: KubeDNSNamespace, Name: "kube-dns-v4"}, es); err != nil {
		t.Fatal(err)
	}
	es.Endpoints = []discoveryv1.Endpoint{{Addresses: []string{"10.42.0.7"}}}
	if err := c.Update(ctx, es); err != nil {
		t.Fatal(err)
	}
	// A failed apply is returned (the request is retried) and applied again.
	fail = true
	if err := reconcile(); err == nil {
		t.Fatal("a failed apply was not reported")
	}
	fail = false
	if err := reconcile(); err != nil {
		t.Fatal(err)
	}
	if len(applied) != 2 || !slices.Equal(applied[1], []string{"10.42.0.7", "10.43.0.10"}) {
		t.Fatalf("applied %v", applied)
	}
}
