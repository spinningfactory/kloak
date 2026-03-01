package webhook

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/go-logr/logr"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestIsEnabled(t *testing.T) {
	// Setup fake client with namespaces and workloads
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)

	nsDefault := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}
	nsEnabled := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "enabled-ns",
			Labels: map[string]string{
				AnnotationEnabled: "true",
			},
		},
	}

	// Workload objects for inheritance testing
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "enabled-deploy",
			Namespace: "default",
			Labels: map[string]string{
				AnnotationEnabled: "true",
			},
		},
	}

	rs := &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "enabled-deploy-rs",
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind: "Deployment",
					Name: "enabled-deploy",
				},
			},
		},
	}

	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "enabled-ds",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationEnabled: "true",
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(nsDefault, nsEnabled, deployment, rs, ds).Build()

	h := &Handler{
		client: fakeClient,
		log:    logr.Discard(),
	}

	tests := []struct {
		name      string
		pod       *corev1.Pod
		namespace string
		expected  bool
	}{
		{
			name:      "no annotations, default ns",
			pod:       &corev1.Pod{},
			namespace: "default",
			expected:  false,
		},
		{
			name: "explicit enabled=true",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						AnnotationEnabled: "true",
					},
				},
			},
			namespace: "default",
			expected:  true,
		},
		{
			name: "explicit enabled=false",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						AnnotationEnabled: "false",
					},
				},
			},
			namespace: "default",
			expected:  false,
		},
		{
			name:      "inheritance from enabled namespace",
			pod:       &corev1.Pod{},
			namespace: "enabled-ns",
			expected:  true,
		},
		{
			name: "disabled pod in enabled namespace",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						AnnotationEnabled: "false",
					},
				},
			},
			namespace: "enabled-ns",
			expected:  false,
		},
		{
			name: "inheritance from deployment (via RS)",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind: "ReplicaSet",
							Name: "enabled-deploy-rs",
						},
					},
				},
			},
			namespace: "default",
			expected:  true,
		},
		{
			name: "inheritance from daemonset",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					OwnerReferences: []metav1.OwnerReference{
						{
							Kind: "DaemonSet",
							Name: "enabled-ds",
						},
					},
				},
			},
			namespace: "default",
			expected:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := h.isEnabled(context.Background(), tc.pod, tc.namespace)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tc.expected {
				t.Errorf("isEnabled() = %v, want %v", result, tc.expected)
			}
		})
	}
}

func TestRewriteSecretVolumes(t *testing.T) {
	// Setup fake client
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	enabledSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-secret",
			Namespace: "default",
			Labels: map[string]string{
				"getkloak.io/enabled": "true",
			},
		},
	}

	disabledSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "other-secret",
			Namespace: "default",
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(enabledSecret, disabledSecret).Build()

	// Use discard logger
	h := &Handler{
		client: fakeClient,
		log:    logr.Discard(),
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{
					Name: "vol-enabled",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: "my-secret",
						},
					},
				},
				{
					Name: "vol-disabled",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: "other-secret",
						},
					},
				},
				{
					Name: "vol-missing",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: "missing-secret",
						},
					},
				},
			},
		},
	}

	err := h.rewriteSecretVolumes(context.Background(), pod, "default")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify "my-secret" rewrote to "my-secret-kloak"
	if pod.Spec.Volumes[0].Secret.SecretName != "my-secret-kloak" {
		t.Errorf("Expected my-secret-kloak, got %s", pod.Spec.Volumes[0].Secret.SecretName)
	}

	// Verify "other-secret" stayed same
	if pod.Spec.Volumes[1].Secret.SecretName != "other-secret" {
		t.Errorf("Expected other-secret, got %s", pod.Spec.Volumes[1].Secret.SecretName)
	}

}
