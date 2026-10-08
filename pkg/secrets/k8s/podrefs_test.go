package k8s

import (
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/spinningfactory/kloak/pkg/secrets"
)

func secretVolume(name string, items ...string) corev1.Volume {
	vs := &corev1.SecretVolumeSource{SecretName: name}
	for _, k := range items {
		vs.Items = append(vs.Items, corev1.KeyToPath{Key: k, Path: k})
	}
	return corev1.Volume{Name: name, VolumeSource: corev1.VolumeSource{Secret: vs}}
}

func keyRef(name, key string) corev1.EnvVar {
	return corev1.EnvVar{Name: "V", ValueFrom: &corev1.EnvVarSource{
		SecretKeyRef: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: name}, Key: key,
		},
	}}
}

func envFrom(name string) corev1.EnvFromSource {
	return corev1.EnvFromSource{SecretRef: &corev1.SecretEnvSource{
		LocalObjectReference: corev1.LocalObjectReference{Name: name},
	}}
}

func TestPodSecretRefs(t *testing.T) {
	tests := []struct {
		name string
		spec corev1.PodSpec
		want []secrets.Ref
	}{
		{
			name: "no references",
			spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}},
			want: []secrets.Ref{},
		},
		{
			name: "secret volume grants every key",
			spec: corev1.PodSpec{Volumes: []corev1.Volume{secretVolume("api-kloak")}},
			want: []secrets.Ref{{OwnerID: "ns/api"}},
		},
		{
			name: "volume items narrow to those keys",
			spec: corev1.PodSpec{Volumes: []corev1.Volume{secretVolume("api-kloak", "token", "id")}},
			want: []secrets.Ref{{OwnerID: "ns/api", Keys: []string{"id", "token"}}},
		},
		{
			name: "secretKeyRef grants one key, merged across containers",
			spec: corev1.PodSpec{
				InitContainers: []corev1.Container{{Name: "init", Env: []corev1.EnvVar{keyRef("api-kloak", "id")}}},
				Containers:     []corev1.Container{{Name: "app", Env: []corev1.EnvVar{keyRef("api-kloak", "token")}}},
			},
			want: []secrets.Ref{{OwnerID: "ns/api", Keys: []string{"id", "token"}}},
		},
		{
			name: "envFrom widens a key reference to every key",
			spec: corev1.PodSpec{Containers: []corev1.Container{{
				Name:    "app",
				Env:     []corev1.EnvVar{keyRef("api-kloak", "token")},
				EnvFrom: []corev1.EnvFromSource{envFrom("api-kloak")},
			}}},
			want: []secrets.Ref{{OwnerID: "ns/api"}},
		},
		{
			name: "every-key grant is not narrowed by a later key reference",
			spec: corev1.PodSpec{
				Volumes:    []corev1.Volume{secretVolume("api-kloak")},
				Containers: []corev1.Container{{Name: "app", Env: []corev1.EnvVar{keyRef("api-kloak", "token")}}},
			},
			want: []secrets.Ref{{OwnerID: "ns/api"}},
		},
		{
			name: "projected secret source",
			spec: corev1.PodSpec{Volumes: []corev1.Volume{{
				Name: "proj",
				VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{{Secret: &corev1.SecretProjection{
						LocalObjectReference: corev1.LocalObjectReference{Name: "db-kloak"},
						Items:                []corev1.KeyToPath{{Key: "password", Path: "p"}},
					}}},
				}},
			}}},
			want: []secrets.Ref{{OwnerID: "ns/db", Keys: []string{"password"}}},
		},
		{
			name: "plain secrets and a bare suffix are ignored",
			spec: corev1.PodSpec{
				Volumes:    []corev1.Volume{secretVolume("tls-cert"), secretVolume("-kloak")},
				Containers: []corev1.Container{{Name: "app", Env: []corev1.EnvVar{keyRef("db", "password")}}},
			},
			want: []secrets.Ref{},
		},
		{
			name: "sorted by owner",
			spec: corev1.PodSpec{Volumes: []corev1.Volume{secretVolume("b-kloak"), secretVolume("a-kloak")}},
			want: []secrets.Ref{{OwnerID: "ns/a"}, {OwnerID: "ns/b"}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "p"}, Spec: tc.spec}
			if got := PodSecretRefs(pod); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("PodSecretRefs() = %#v, want %#v", got, tc.want)
			}
		})
	}
}
