package controller

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func uninstallScheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	_ = appsv1.AddToScheme(s)
	return s
}

func TestUninstallWatcher(t *testing.T) {
	ds := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "kloak-controller", Namespace: "kloak"}}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "kloak-controller-x", Namespace: "kloak"},
		Status:     corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
	}
	c := fake.NewClientBuilder().WithScheme(uninstallScheme()).WithObjects(ds, pod).WithStatusSubresource(&corev1.Pod{}).Build()
	calls := 0
	w := &UninstallWatcher{Client: c, Namespace: "kloak", Name: "kloak-controller", PodName: pod.Name,
		Uninstall: func() error { calls++; return nil }, Log: zap.NewNop().Sugar()}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "kloak", Name: "kloak-controller"}}

	// No annotation: a rollout, nothing to tear down.
	if _, err := w.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if calls != 0 || w.Uninstalled() || w.ReadyCheck(nil) != nil {
		t.Fatalf("torn down without the annotation (calls %d)", calls)
	}

	ds.Annotations = map[string]string{UninstallAnnotation: time.Now().UTC().Format(time.RFC3339)}
	if err := c.Update(context.Background(), ds); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := w.Reconcile(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Errorf("Uninstall ran %d times, want once", calls)
	}
	if !w.Uninstalled() || w.ReadyCheck(nil) == nil {
		t.Error("still ready after the teardown")
	}
	got := &corev1.Pod{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "kloak", Name: pod.Name}, got); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, cond := range got.Status.Conditions {
		if cond.Type == UninstalledCondition && cond.Status == corev1.ConditionTrue {
			found = true
		}
	}
	if !found || len(got.Status.Conditions) != 2 {
		t.Errorf("pod conditions %+v, want Ready kept and %s=True", got.Status.Conditions, UninstalledCondition)
	}
}

func TestWaitForInitialReconcile(t *testing.T) {
	enabled := func(name, uid, node string, phase corev1.PodPhase) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns", UID: types.UID(uid),
				Annotations: map[string]string{AnnotationEnabled: "true"}},
			Spec:   corev1.PodSpec{NodeName: node},
			Status: corev1.PodStatus{Phase: phase},
		}
	}
	plain := enabled("plain", "u-plain", "node-1", corev1.PodRunning)
	plain.Annotations = nil
	c := fake.NewClientBuilder().WithScheme(uninstallScheme()).WithObjects(
		enabled("a", "u-a", "node-1", corev1.PodRunning),
		enabled("b", "u-b", "node-1", corev1.PodPending),
		enabled("other-node", "u-o", "node-2", corev1.PodRunning),
		enabled("done", "u-d", "node-1", corev1.PodSucceeded),
		plain,
	).Build()
	r := NewReconciler(c, zap.NewNop().Sugar(), uninstallScheme(), nil, "", "node-1")

	pending := r.WaitForInitialReconcile(context.Background(), 600*time.Millisecond)
	if len(pending) != 2 {
		t.Fatalf("pending %v, want ns/a and ns/b", pending)
	}
	r.markReconciled("u-a")
	go func() {
		time.Sleep(300 * time.Millisecond)
		r.markReconciled("u-b")
	}()
	if pending := r.WaitForInitialReconcile(context.Background(), 5*time.Second); len(pending) != 0 {
		t.Errorf("pending %v after both pods were reconciled", pending)
	}
}
