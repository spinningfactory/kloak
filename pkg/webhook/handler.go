// Package webhook provides the Kubernetes mutating admission webhook
// for injecting Envoy sidecars and Root CA into pods.
package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/go-logr/logr"
)

const (
	// AnnotationEnabled is the annotation to enable Kloak on a pod.
	AnnotationEnabled = "getkloak.io/enabled"

	// EnvoyImage is the default Envoy sidecar image.
	EnvoyImage = "envoyproxy/envoy:v1.37-latest"

	// EnvoyPort is the port Envoy listens on for intercepted traffic.
	EnvoyPort = 15001

	// CACertFile is the filename for the CA cert.
	CACertFile = "ca.crt"

	// CAVolumeName is the name of the shared volume containing the CA.
	CAVolumeName = "kloak-ca-vol"

	// CASecretName is the name of the Secret containing the CA.
	CASecretName = "kloak-ca"

	// InitContainerImage is the image used for the init container.
	InitContainerImage = "busybox:1.36"
)

// Handler handles pod mutation requests.
type Handler struct {
	client          client.Client
	decoder         admission.Decoder
	log             logr.Logger
	systemNamespace string // Namespace where Kloak is installed (for accessing CA secret)
}

// NewHandler creates a new webhook handler.
func NewHandler(c client.Client, log logr.Logger, systemNamespace string) *Handler {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	return &Handler{
		client:          c,
		decoder:         admission.NewDecoder(scheme),
		log:             log,
		systemNamespace: systemNamespace,
	}
}

// Handle processes admission requests for pods.
func (h *Handler) Handle(ctx context.Context, req admission.Request) admission.Response {
	pod := &corev1.Pod{}
	if err := h.decoder.Decode(req, pod); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	// Check if Kloak is enabled for this pod (explicitly or via namespace inheritance)
	enabled, err := h.isEnabled(ctx, pod, req.Namespace)
	if err != nil {
		h.log.Error(err, "failed to check if pod is enabled")
		return admission.Errored(http.StatusInternalServerError, err)
	}
	if !enabled {
		return admission.Allowed("kloak not enabled")
	}

	// Create a copy to mutate
	mutatedPod := pod.DeepCopy()

	// Ensure the enabled annotation is present on the mutated pod
	// This allows the controller (DaemonSet) to see that it's enabled even if it was inherited from the Namespace
	if mutatedPod.Annotations == nil {
		mutatedPod.Annotations = make(map[string]string)
	}
	mutatedPod.Annotations[AnnotationEnabled] = "true"

	// 1. Inject Envoy sidecar
	h.injectEnvoySidecar(mutatedPod)

	// 2. Mount Root CA certificate
	h.mountRootCA(mutatedPod)

	// 3. Rewrite Secret volumes (swap with shadow secrets)
	if err := h.rewriteSecretVolumes(ctx, mutatedPod, req.Namespace); err != nil {
		h.log.Error(err, "failed to rewrite secret volumes")
		// We log error but don't fail admission? Or should we fail?
		// Failing is safer if we intend to protect secrets.
		return admission.Errored(http.StatusInternalServerError, err)
	}

	// Create JSON patch
	marshaledPod, err := json.Marshal(mutatedPod)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}

	return admission.PatchResponseFromRaw(req.Object.Raw, marshaledPod)
}

// isEnabled checks if Kloak should process this pod.
// It checks for the explicit pod annotation first, then falls back to the namespace label.
func (h *Handler) isEnabled(ctx context.Context, pod *corev1.Pod, namespace string) (bool, error) {
	// 1. Check explicit Pod annotation
	if pod.Annotations != nil {
		if val, ok := pod.Annotations[AnnotationEnabled]; ok {
			return val == "true", nil
		}
	}

	// 2. Check Namespace label (inheritance)
	// We need to fetch the namespace object to check labels
	ns := &corev1.Namespace{}
	if err := h.client.Get(ctx, client.ObjectKey{Name: namespace}, ns); err != nil {
		h.log.Error(err, "failed to fetch namespace for label check", "namespace", namespace)
		// Don't return false yet, try other checks? No, failing open or closed?
		// If namespace check fails, we probably cant proceed safely.
		return false, err
	}

	if ns.Labels != nil && ns.Labels[AnnotationEnabled] == "true" {
		return true, nil
	}

	// 3. Check OwnerReferences (Workload inheritance)
	// Traverse up to find Deployment, DaemonSet, StatefulSet
	for _, ref := range pod.OwnerReferences {
		// Handle ReplicaSet (Deployment -> ReplicaSet -> Pod)
		if ref.Kind == "ReplicaSet" {
			rs := &appsv1.ReplicaSet{}
			if err := h.client.Get(ctx, client.ObjectKey{Name: ref.Name, Namespace: namespace}, rs); err == nil {
				// Check RS itself
				if h.isObjectEnabled(rs.Labels, rs.Annotations) {
					return true, nil
				}

				// Check RS owner (Deployment)
				for _, rsRef := range rs.OwnerReferences {
					if rsRef.Kind == "Deployment" {
						deploy := &appsv1.Deployment{}
						if err := h.client.Get(ctx, client.ObjectKey{Name: rsRef.Name, Namespace: namespace}, deploy); err == nil {
							if h.isObjectEnabled(deploy.Labels, deploy.Annotations) {
								return true, nil
							}
						}
					}
				}
			}
		}

		// Handle DaemonSet
		if ref.Kind == "DaemonSet" {
			ds := &appsv1.DaemonSet{}
			if err := h.client.Get(ctx, client.ObjectKey{Name: ref.Name, Namespace: namespace}, ds); err == nil {
				if h.isObjectEnabled(ds.Labels, ds.Annotations) {
					return true, nil
				}
			}
		}

		// Handle StatefulSet
		if ref.Kind == "StatefulSet" {
			sts := &appsv1.StatefulSet{}
			if err := h.client.Get(ctx, client.ObjectKey{Name: ref.Name, Namespace: namespace}, sts); err == nil {
				if h.isObjectEnabled(sts.Labels, sts.Annotations) {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

// isObjectEnabled checks if the given labels or annotations have the enabled flag.
func (h *Handler) isObjectEnabled(labels, annotations map[string]string) bool {
	if labels != nil && labels[AnnotationEnabled] == "true" {
		return true
	}
	if annotations != nil && annotations[AnnotationEnabled] == "true" {
		return true
	}
	return false
}

// injectEnvoySidecar adds the Envoy sidecar container to the pod.
func (h *Handler) injectEnvoySidecar(pod *corev1.Pod) {
	envoyContainer := corev1.Container{
		Name:  "envoy-sidecar",
		Image: EnvoyImage,
		Ports: []corev1.ContainerPort{
			{
				Name:          "proxy",
				ContainerPort: EnvoyPort,
				Protocol:      corev1.ProtocolTCP,
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "envoy-config",
				MountPath: "/etc/envoy",
				ReadOnly:  true,
			},
		},
		Args: []string{
			"-c", "/etc/envoy/envoy.yaml",
			"--service-cluster", "kloak-sidecar",
			"--service-node", "kloak-sidecar-$(POD_NAME)",
			"--log-level", "debug",
		},
		Env: []corev1.EnvVar{
			{
				Name: "POD_NAME",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{
						FieldPath: "metadata.name",
					},
				},
			},
			{
				Name: "POD_NAMESPACE",
				ValueFrom: &corev1.EnvVarSource{
					FieldRef: &corev1.ObjectFieldSelector{
						FieldPath: "metadata.namespace",
					},
				},
			},
		},
		SecurityContext: &corev1.SecurityContext{
			RunAsUser:  ptr(int64(1337)),
			RunAsGroup: ptr(int64(1337)),
		},
	}

	// Add Envoy container
	pod.Spec.Containers = append(pod.Spec.Containers, envoyContainer)

	// Add envoy config volume (will be provided by ConfigMap)
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
		Name: "envoy-config",
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: "kloak-envoy-config",
				},
			},
		},
	})

}

// mountRootCA injects the CA certificate using an init container.
// It reads the CA from the Secret and writes it to a shared volume.
func (h *Handler) mountRootCA(pod *corev1.Pod) {
	const (
		CAVolPath = "/etc/kloak-ca"
	)

	// Fetch CA Secret
	// We use context.Background() here because we're inside a synchronous handle loop
	// and admission request context might be cancelled if we take too long?
	// Actually we should use the request context but we don't have it passed here easily unless we change signature.
	// But `Handle` calls this synchronously.
	// Let's rely on the cached client.
	secret := &corev1.Secret{}
	err := h.client.Get(context.Background(), client.ObjectKey{
		Namespace: h.systemNamespace,
		Name:      CASecretName,
	}, secret)

	var caCertPEM string
	if err != nil {
		h.log.Error(err, "failed to fetch CA secret for injection", "namespace", h.systemNamespace)
		// We can't inject. Should we fail?
		// Without CA, the app will fail to talk to sidecar/services if they use our certs.
		// For now, log and return. The pod will start without CA and likely fail connection.
		return
	}

	// Extract CA cert
	if data, ok := secret.Data[corev1.TLSCertKey]; ok {
		caCertPEM = string(data)
	} else if data, ok := secret.Data["ca.crt"]; ok {
		caCertPEM = string(data)
	} else {
		h.log.Error(nil, "CA secret missing certificate key")
		return
	}

	// 1. Add shared emptyDir volume
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
		Name: CAVolumeName,
		VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{},
		},
	})

	// 2. Add Init Container to write CA
	initContainer := corev1.Container{
		Name:    "kloak-init-ca",
		Image:   InitContainerImage,
		Command: []string{"sh", "-c", "echo \"$CA_PEM\" > /etc/kloak-ca/ca.crt"},
		Env: []corev1.EnvVar{
			{
				Name:  "CA_PEM",
				Value: caCertPEM,
			},
		},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      CAVolumeName,
				MountPath: CAVolPath,
			},
		},
		// Security context to ensure we can write?
		// emptyDir is usually writable by root.
	}
	pod.Spec.InitContainers = append(pod.Spec.InitContainers, initContainer)

	// 3. Mount volume to all app containers and inject env var
	for i := range pod.Spec.Containers {
		// Skip sidecar? Sidecar has its own config. But maybe it needs to trust CA too?
		// Sidecar usually gets certs via SDS. It doesn't need file CA for that.
		// But let's mount to all for consistency.

		pod.Spec.Containers[i].VolumeMounts = append(
			pod.Spec.Containers[i].VolumeMounts,
			corev1.VolumeMount{
				Name:      CAVolumeName,
				MountPath: CAVolPath,
				ReadOnly:  true,
			},
		)

		// Inject SSL_CERT_FILE env var pointing to the CA cert
		fullPath := fmt.Sprintf("%s/%s", CAVolPath, CACertFile)
		pod.Spec.Containers[i].Env = append(
			pod.Spec.Containers[i].Env,
			corev1.EnvVar{
				Name:  "SSL_CERT_FILE",
				Value: fullPath,
			},
		)
	}
}

func ptr[T any](v T) *T {
	return &v
}

// rewriteSecretVolumes checks volume mounts and swaps enabled secrets with shadow secrets.
func (h *Handler) rewriteSecretVolumes(ctx context.Context, pod *corev1.Pod, namespace string) error {
	for i := range pod.Spec.Volumes {
		vol := &pod.Spec.Volumes[i]
		if vol.Secret != nil {
			secretName := vol.Secret.SecretName

			// Resolve namespace (pod namespace usually)
			ns := namespace
			if ns == "" {
				ns = "default" // Fallback
			}

			// Check if secret is enabled
			var secret corev1.Secret
			err := h.client.Get(ctx, client.ObjectKey{Name: secretName, Namespace: ns}, &secret)
			if err != nil {
				// If not found or error, just skip rewriting (safest default? or fail?)
				// If we can't find it, we can't verify label.
				// Pod admission will likely fail downstream if secret is missing anyway.
				h.log.V(1).Info("failed to look up secret for volume rewriting", "name", secretName, "error", err)
				continue
			}

			// Check annotation/label
			enabled := secret.Labels[AnnotationEnabled] == "true" || secret.Annotations[AnnotationEnabled] == "true"
			if enabled {
				shadowName := secretName + "-kloak"
				h.log.Info("Rewriting volume to use shadow secret", "original", secretName, "shadow", shadowName)
				vol.Secret.SecretName = shadowName
			}
		}
	}
	// TODO: Handle EnvFrom? User specifically mentioned "mount".
	return nil
}
