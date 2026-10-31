package webhook

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestRewriteSecretVolumes_ProjectedSources(t *testing.T) {
	enabled := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: "credentials", Namespace: "default",
		Labels: map[string]string{LabelEnabled: "true"},
	}}
	shadow := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: "credentials-kloak", Namespace: "default",
		Labels: map[string]string{"getkloak.io/managed": "true"},
	}}
	disabled := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: "unmanaged", Namespace: "default",
	}}
	optional := true
	mode := int32(0400)
	expires := int64(3600)
	pod := &corev1.Pod{Spec: corev1.PodSpec{
		Volumes: []corev1.Volume{
			{
				Name: "direct",
				VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
					SecretName: "credentials",
				}},
			},
			{
				Name: "combined",
				VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
					DefaultMode: &mode,
					Sources: []corev1.VolumeProjection{
						{ConfigMap: &corev1.ConfigMapProjection{
							LocalObjectReference: corev1.LocalObjectReference{Name: "settings"},
						}},
						{Secret: &corev1.SecretProjection{
							LocalObjectReference: corev1.LocalObjectReference{Name: "credentials"},
							Items:                []corev1.KeyToPath{{Key: "api-key", Path: "api/key", Mode: &mode}},
						}},
						{Secret: &corev1.SecretProjection{
							LocalObjectReference: corev1.LocalObjectReference{Name: "unmanaged"},
						}},
						{Secret: &corev1.SecretProjection{
							LocalObjectReference: corev1.LocalObjectReference{Name: "credentials"},
							Optional:             &optional,
							Items:                []corev1.KeyToPath{{Key: "api-key", Path: "optional/key"}},
						}},
						{Secret: &corev1.SecretProjection{
							LocalObjectReference: corev1.LocalObjectReference{Name: "missing"},
							Optional:             &optional,
						}},
						{DownwardAPI: &corev1.DownwardAPIProjection{
							Items: []corev1.DownwardAPIVolumeFile{{
								Path: "namespace", FieldRef: &corev1.ObjectFieldSelector{FieldPath: "metadata.namespace"},
							}},
						}},
						{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
							Audience: "api", ExpirationSeconds: &expires, Path: "token",
						}},
					},
				}},
			},
		},
	}}
	want := pod.DeepCopy()
	want.Spec.Volumes[0].Secret.SecretName = "credentials-kloak"
	want.Spec.Volumes[1].Projected.Sources[1].Secret.Name = "credentials-kloak"
	want.Spec.Volumes[1].Projected.Sources[3].Secret.Name = "credentials-kloak"

	// The empty namespace must retain the direct-volume defaulting behavior.
	for _, namespace := range []string{"default", ""} {
		t.Run(fmt.Sprintf("namespace=%q", namespace), func(t *testing.T) {
			got := pod.DeepCopy()
			h := newTestHandler(enabled, shadow, disabled)
			if err := h.rewriteSecretVolumes(context.Background(), got, namespace); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("expected only enabled secret references to change; got volumes: %+v", got.Spec.Volumes)
			}
		})
	}
}

func TestHandle_ProjectedSecretAdmission(t *testing.T) {
	for _, shadowState := range []string{"managed", "missing", "unmanaged"} {
		for _, optional := range []bool{false, true} {
			t.Run(fmt.Sprintf("shadow=%s/optional=%t", shadowState, optional), func(t *testing.T) {
				objs := []client.Object{
					&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
						Name: "default", Labels: map[string]string{LabelEnabled: "true"},
					}},
					&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
						Name: "credentials", Namespace: "default",
						Labels: map[string]string{LabelEnabled: "true"},
					}},
				}
				if shadowState != "missing" {
					shadow := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
						Name: "credentials-kloak", Namespace: "default",
					}}
					if shadowState == "managed" {
						shadow.Labels = map[string]string{"getkloak.io/managed": "true"}
					}
					objs = append(objs, shadow)
				}
				pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
					Name: "app", Namespace: "default",
				}, Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "app", Image: "busybox"}},
					Volumes: []corev1.Volume{{
						Name: "credentials",
						VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
							Sources: []corev1.VolumeProjection{{Secret: &corev1.SecretProjection{
								LocalObjectReference: corev1.LocalObjectReference{Name: "credentials"},
								Optional:             &optional,
							}}},
						}},
					}},
				}}
				resp := newTestHandler(objs...).Handle(context.Background(), makeAdmissionRequest(pod, "default"))
				if shadowState != "managed" {
					if resp.Allowed {
						t.Fatal("pod admitted with an enabled projected secret but no valid shadow")
					}
					if resp.Result == nil || !strings.Contains(resp.Result.Message, "shadow secret") {
						t.Fatalf("expected shadow-secret denial, got %v", resp.Result)
					}
					return
				}
				if !resp.Allowed {
					t.Fatalf("expected admission with a valid shadow: %v", resp.Result)
				}
				for _, patch := range resp.Patches {
					if patch.Path == "/spec/volumes/0/projected/sources/0/secret/name" && patch.Value == "credentials-kloak" {
						return
					}
				}
				t.Fatalf("missing projected-secret rewrite in admission patches: %+v", resp.Patches)
			})
		}
	}
}
