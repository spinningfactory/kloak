package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/spinningfactory/kloak/pkg/controller"
	"github.com/spinningfactory/kloak/pkg/ebpf"
)

func persistScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = appsv1.AddToScheme(s)
	return s
}

func controllerDS(mutate func(*appsv1.DaemonSet)) *appsv1.DaemonSet {
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: "kloak-controller", Namespace: "kloak"},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "kloak-controller"}},
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{controller.PinFormatAnnotation: "1"},
			}},
		},
	}
	if mutate != nil {
		mutate(ds)
	}
	return ds
}

// failingReader fails every Get with err.
func failingReader(err error) client.Reader {
	return fake.NewClientBuilder().WithScheme(persistScheme()).WithInterceptorFuncs(interceptor.Funcs{
		Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
			return err
		},
	}).Build()
}

func TestShutdownMode(t *testing.T) {
	gr := schema.GroupResource{Group: "apps", Resource: "daemonsets"}
	now := metav1.Now()
	for _, c := range []struct {
		name        string
		reader      client.Reader
		uninstalled bool
		want        ebpf.ShutdownMode
	}{
		{"the DaemonSet stays", fake.NewClientBuilder().WithScheme(persistScheme()).WithObjects(controllerDS(nil)).Build(), false, ebpf.ShutdownKeep},
		{"already torn down", fake.NewClientBuilder().WithScheme(persistScheme()).WithObjects(controllerDS(nil)).Build(), true, ebpf.ShutdownUninstall},
		{"annotated for uninstall", fake.NewClientBuilder().WithScheme(persistScheme()).WithObjects(controllerDS(func(ds *appsv1.DaemonSet) {
			ds.Annotations = map[string]string{controller.UninstallAnnotation: "2026-11-08T00:00:00Z"}
		})).Build(), false, ebpf.ShutdownUninstall},
		{"being deleted", fake.NewClientBuilder().WithScheme(persistScheme()).WithObjects(controllerDS(func(ds *appsv1.DaemonSet) {
			ds.DeletionTimestamp = &now
			ds.Finalizers = []string{"test"} // the fake client keeps a deleting object only with a finalizer
		})).Build(), false, ebpf.ShutdownUninstall},
		{"rolled out to a version that does not adopt", fake.NewClientBuilder().WithScheme(persistScheme()).WithObjects(controllerDS(func(ds *appsv1.DaemonSet) {
			ds.Spec.Template.Annotations = nil
		})).Build(), false, ebpf.ShutdownDetach},
		{"gone", fake.NewClientBuilder().WithScheme(persistScheme()).Build(), false, ebpf.ShutdownUninstall},
		{"RBAC gone", failingReader(apierrors.NewForbidden(gr, "kloak-controller", errors.New("denied"))), false, ebpf.ShutdownUninstall},
		{"unauthorized", failingReader(apierrors.NewUnauthorized("no")), false, ebpf.ShutdownUninstall},
		{"API server unreachable", failingReader(context.DeadlineExceeded), false, ebpf.ShutdownDetach},
		{"server error", failingReader(apierrors.NewInternalError(errors.New("boom"))), false, ebpf.ShutdownDetach},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, why := shutdownMode(context.Background(), c.reader, "kloak", "kloak-controller", c.uninstalled)
			if got != c.want {
				t.Errorf("mode %v (%s), want %v", got, why, c.want)
			}
		})
	}
}

func TestLockNodeWaitsForTheHolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run", "kloak", "lock")
	log := zap.NewNop().Sugar()
	held, err := lockNode(context.Background(), path, log)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if f, err := lockNode(ctx, path, log); err == nil {
		_ = f.Close()
		t.Fatal("took the node lock while another controller holds it")
	}

	got := make(chan error, 1)
	go func() {
		f, err := lockNode(context.Background(), path, log)
		if err == nil {
			_ = f.Close()
		}
		got <- err
	}()
	time.Sleep(200 * time.Millisecond)
	_ = held.Close() // the previous controller exits
	select {
	case err := <-got:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the lock was not taken once its holder exited")
	}
}

func controllerPod(name, node string, ready bool) *corev1.Pod {
	status := corev1.ConditionFalse
	if ready {
		status = corev1.ConditionTrue
	}
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "kloak", Labels: map[string]string{"app": "kloak-controller"}},
		Spec:       corev1.PodSpec{NodeName: node},
		Status:     corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: status}}},
	}
}

func TestUninstallHook(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(persistScheme()).
		WithObjects(controllerDS(nil),
			controllerPod("a", "node-a", true),
			controllerPod("b", "node-b", true),
			controllerPod("c", "node-c", false)).
		WithStatusSubresource(&corev1.Pod{}).
		Build()
	// node-a's controller tears down once asked; node-b's never reports.
	go func() {
		for {
			ds := &appsv1.DaemonSet{}
			if err := c.Get(context.Background(), types.NamespacedName{Namespace: "kloak", Name: "kloak-controller"}, ds); err == nil &&
				ds.Annotations[controller.UninstallAnnotation] != "" {
				p := &corev1.Pod{}
				_ = c.Get(context.Background(), types.NamespacedName{Namespace: "kloak", Name: "a"}, p)
				p.Status.Conditions = append(p.Status.Conditions, corev1.PodCondition{Type: controller.UninstalledCondition, Status: corev1.ConditionTrue})
				_ = c.Status().Update(context.Background(), p)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	var out bytes.Buffer
	runUninstallHook(context.Background(), c, "kloak", "kloak-controller", 500*time.Millisecond, 20*time.Millisecond, &out, zap.NewNop().Sugar())
	got := out.String()
	for _, want := range []string{
		"asked 2 controllers",
		"torn down: node node-a, pod a",
		"not confirmed: node node-b, pod b (no report within 500ms)",
		"not confirmed: node node-c, pod c (the controller was not ready)",
		"kloak cleanup",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	ds := &appsv1.DaemonSet{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "kloak", Name: "kloak-controller"}, ds); err != nil || ds.Annotations[controller.UninstallAnnotation] == "" {
		t.Errorf("the DaemonSet is not annotated for uninstall: %v %v", ds.Annotations, err)
	}
}

func TestUninstallHookWithoutDaemonSet(t *testing.T) {
	var out bytes.Buffer
	c := fake.NewClientBuilder().WithScheme(persistScheme()).Build()
	runUninstallHook(context.Background(), c, "kloak", "kloak-controller", time.Second, 10*time.Millisecond, &out, zap.NewNop().Sugar())
	if !strings.Contains(out.String(), "no controller to tear down") {
		t.Errorf("output: %s", out.String())
	}
}
