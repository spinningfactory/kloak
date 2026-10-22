package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/spinningfactory/kloak/pkg/ebpf"
)

// procDirWithRoutes writes a /proc/<pid>/net/route with the given
// destination/mask pairs and returns the <pid> directory.
func procDirWithRoutes(t *testing.T, routes ...[2]string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	hex := func(s string) string {
		return fmt.Sprintf("%08X", binary.NativeEndian.Uint32(netip.MustParseAddr(s).AsSlice()))
	}
	var b strings.Builder
	b.WriteString("Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n")
	for _, r := range routes {
		fmt.Fprintf(&b, "eth0\t%s\t00000000\t0001\t0\t0\t0\t%s\t0\t0\t0\n", hex(r[0]), hex(r[1]))
	}
	if err := os.WriteFile(filepath.Join(dir, "net", "route"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// addRoutes6 writes a net/ipv6_route with the given destinations to the
// <pid> directory dir.
func addRoutes6(t *testing.T, dir string, dsts ...string) {
	t.Helper()
	var b strings.Builder
	for _, d := range dsts {
		p := netip.MustParsePrefix(d)
		a := p.Addr().As16()
		fmt.Fprintf(&b, "%x %02x 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n", a[:], p.Bits())
	}
	if err := os.WriteFile(filepath.Join(dir, "net", "ipv6_route"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func clusterReader(funcs interceptor.Funcs, objs ...client.Object) client.Reader {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = networkingv1.AddToScheme(scheme)
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).WithInterceptorFuncs(funcs).Build()
}

// failServiceCIDRList makes listing ServiceCIDRs return err.
func failServiceCIDRList(err error) interceptor.Funcs {
	return interceptor.Funcs{List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
		if _, ok := list.(*networkingv1.ServiceCIDRList); ok {
			return err
		}
		return c.List(ctx, list, opts...)
	}}
}

func testNode(name string, podCIDRs []string, addrs ...string) *corev1.Node {
	n := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: corev1.NodeSpec{PodCIDRs: podCIDRs}}
	for _, a := range addrs {
		n.Status.Addresses = append(n.Status.Addresses, corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: a})
	}
	n.Status.Addresses = append(n.Status.Addresses, corev1.NodeAddress{Type: corev1.NodeHostName, Address: name})
	return n
}

func rangeStrings(rs []ebpf.ReservedRange) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Prefix.String()+" "+r.Source)
	}
	slices.Sort(out)
	return out
}

func TestDiscoverReservedRanges(t *testing.T) {
	reader := clusterReader(interceptor.Funcs{},
		testNode("a", []string{"10.42.0.0/24", "fd00:42::/64"}, "192.168.5.15"),
		testNode("b", nil, "192.168.5.16"),
		&networkingv1.ServiceCIDR{
			ObjectMeta: metav1.ObjectMeta{Name: "kubernetes"},
			Spec:       networkingv1.ServiceCIDRSpec{CIDRs: []string{"10.43.0.0/16"}},
		},
	)
	procDir := procDirWithRoutes(t, [2]string{"0.0.0.0", "0.0.0.0"}, [2]string{"10.42.1.0", "255.255.255.0"})
	addRoutes6(t, procDir, "fd00:6b6c::/64", "::/0")

	got, err := discoverReservedRanges(context.Background(), reader, procDir, zap.NewNop().Sugar())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"0.0.0.0/0 node route via eth0",
		"10.42.0.0/24 pod CIDR of node a",
		"10.42.1.0/24 node route via eth0",
		"10.43.0.0/16 service CIDR kubernetes",
		"192.168.5.15/32 address of node a",
		"192.168.5.16/32 address of node b",
		"::/0 node route via eth0",
		"fd00:42::/64 pod CIDR of node a",
		"fd00:6b6c::/64 node route via eth0",
	}
	if g := rangeStrings(got); !slices.Equal(g, want) {
		t.Fatalf("got\n  %s\nwant\n  %s", strings.Join(g, "\n  "), strings.Join(want, "\n  "))
	}
}

func TestDiscoverReservedRangesWithoutServiceCIDRAPI(t *testing.T) {
	noMatch := &meta.NoKindMatchError{GroupKind: schema.GroupKind{Group: "networking.k8s.io", Kind: "ServiceCIDR"}}
	reader := clusterReader(failServiceCIDRList(noMatch),
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "kubernetes", Namespace: "default"},
			Spec:       corev1.ServiceSpec{ClusterIP: "10.43.0.1", ClusterIPs: []string{"10.43.0.1"}},
		},
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system"},
			Spec:       corev1.ServiceSpec{ClusterIP: "10.43.0.10", ClusterIPs: []string{"10.43.0.10"}},
		},
	)
	got, err := discoverReservedRanges(context.Background(), reader, procDirWithRoutes(t), zap.NewNop().Sugar())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"10.43.0.1/32 ClusterIP of service default/kubernetes",
		"10.43.0.10/32 ClusterIP of service kube-system/kube-dns",
	}
	if g := rangeStrings(got); !slices.Equal(g, want) {
		t.Fatalf("got %v, want %v", g, want)
	}
}

func TestDiscoverReservedRangesFailsClosed(t *testing.T) {
	forbidden := apierrors.NewForbidden(schema.GroupResource{Group: "networking.k8s.io", Resource: "servicecidrs"}, "", fmt.Errorf("rbac"))
	if _, err := discoverReservedRanges(context.Background(), clusterReader(failServiceCIDRList(forbidden)),
		procDirWithRoutes(t), zap.NewNop().Sugar()); err == nil {
		t.Error("a forbidden ServiceCIDR list did not fail")
	}
	if _, err := discoverReservedRanges(context.Background(), clusterReader(interceptor.Funcs{}),
		filepath.Join(t.TempDir(), "missing"), zap.NewNop().Sugar()); err == nil {
		t.Error("unreadable node routes did not fail")
	}
}

func TestCheckVirtualIPRangesController(t *testing.T) {
	defaults, err := ebpf.ParseVirtualIPRanges(ebpf.DefaultVirtualIPRange)
	if err != nil {
		t.Fatal(err)
	}
	reader := clusterReader(interceptor.Funcs{}, testNode("a", []string{"10.42.0.0/24", "2001:2:0:1::/64"}, "198.19.0.5"))
	err = checkVirtualIPRanges(context.Background(), reader, defaults, procDirWithRoutes(t), zap.NewNop().Sugar())
	for _, want := range []string{"198.19.0.5/32 (address of node a)", "2001:2:0:1::/64 (pod CIDR of node a)"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("overlap %s not reported: %v", want, err)
		}
	}
	// The IPv6 range against a node's IPv6 routes.
	procDir := procDirWithRoutes(t)
	addRoutes6(t, procDir, "2001:2::/64")
	clean := clusterReader(interceptor.Funcs{}, testNode("a", []string{"10.42.0.0/24"}, "192.168.5.15"))
	if err := checkVirtualIPRanges(context.Background(), clean, defaults, procDir, zap.NewNop().Sugar()); err == nil ||
		!strings.Contains(err.Error(), "2001:2::/64 (node route via eth0)") {
		t.Errorf("overlap with a node IPv6 route not reported: %v", err)
	}
	other := ebpf.VirtualIPRanges{V4: netip.MustParsePrefix("100.120.0.0/16"), V6: netip.MustParsePrefix("fd00:6b6c:1::/64")}
	if err := checkVirtualIPRanges(context.Background(), reader, other, procDirWithRoutes(t), zap.NewNop().Sugar()); err != nil {
		t.Fatalf("non-overlapping ranges refused: %v", err)
	}
}
