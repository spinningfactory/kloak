// Package webhook provides the Kubernetes mutating admission webhook
// for injecting Envoy sidecars and Root CA into pods.
package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/dhia/bouncer/pkg/hash"
	"github.com/dhia/bouncer/pkg/storage"
)

const (
	// AnnotationEnabled is the annotation to enable Bouncer on a pod.
	AnnotationEnabled = "bouncer.io/enabled"

	// AnnotationHashedEnvs lists env vars that were hashed.
	AnnotationHashedEnvs = "bouncer.io/hashed-envs"

	// EnvoyImage is the default Envoy sidecar image.
	EnvoyImage = "envoyproxy/envoy:v1.29-latest"

	// EnvoyPort is the port Envoy listens on for intercepted traffic.
	EnvoyPort = 15001

	// CAMountPath is where the Root CA certificate is mounted.
	CAMountPath = "/etc/ssl/certs/bouncer-ca.crt"

	// CAVolumeName is the name of the volume containing the CA.
	CAVolumeName = "bouncer-ca"

	// CAConfigMapName is the name of the ConfigMap containing the CA cert.
	CAConfigMapName = "bouncer-ca-cert"
)

// Handler handles pod mutation requests.
type Handler struct {
	client     client.Client
	decoder    admission.Decoder
	storage    storage.Storage
	envsToHash []string // Environment variable names to hash
}

// NewHandler creates a new webhook handler.
func NewHandler(c client.Client, store storage.Storage, envsToHash []string) *Handler {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	return &Handler{
		client:     c,
		storage:    store,
		envsToHash: envsToHash,
		decoder:    admission.NewDecoder(scheme),
	}
}

// Handle processes admission requests for pods.
func (h *Handler) Handle(ctx context.Context, req admission.Request) admission.Response {
	pod := &corev1.Pod{}
	if err := h.decoder.Decode(req, pod); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	// Check if Bouncer is enabled for this pod
	if !h.isEnabled(pod) {
		return admission.Allowed("bouncer not enabled")
	}

	// Create a copy to mutate
	mutatedPod := pod.DeepCopy()

	// 1. Inject Envoy sidecar
	h.injectEnvoySidecar(mutatedPod)

	// 2. Mount Root CA certificate
	h.mountRootCA(mutatedPod)

	// 3. Hash sensitive environment variables
	podID := fmt.Sprintf("%s/%s", req.Namespace, req.Name)
	if req.Name == "" {
		podID = fmt.Sprintf("%s/%s", req.Namespace, mutatedPod.GenerateName)
	}
	h.hashEnvVars(ctx, mutatedPod, podID)

	// Create JSON patch
	marshaledPod, err := json.Marshal(mutatedPod)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}

	return admission.PatchResponseFromRaw(req.Object.Raw, marshaledPod)
}

// isEnabled checks if Bouncer should process this pod.
func (h *Handler) isEnabled(pod *corev1.Pod) bool {
	if pod.Annotations == nil {
		return false
	}
	return pod.Annotations[AnnotationEnabled] == "true"
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
			{
				Name:      CAVolumeName,
				MountPath: "/etc/bouncer",
				ReadOnly:  true,
			},
		},
		Args: []string{
			"-c", "/etc/envoy/envoy.yaml",
			"--log-level", "info",
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
					Name: "bouncer-envoy-config",
				},
			},
		},
	})
}

// mountRootCA adds the Root CA certificate volume to the pod.
func (h *Handler) mountRootCA(pod *corev1.Pod) {
	// Add CA volume
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
		Name: CAVolumeName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: CAConfigMapName,
				},
			},
		},
	})

	// Mount CA into all app containers (not the Envoy sidecar)
	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == "envoy-sidecar" {
			continue
		}
		pod.Spec.Containers[i].VolumeMounts = append(
			pod.Spec.Containers[i].VolumeMounts,
			corev1.VolumeMount{
				Name:      CAVolumeName,
				MountPath: CAMountPath,
				SubPath:   "ca.crt",
				ReadOnly:  true,
			},
		)
	}
}

// hashEnvVars hashes specified environment variables and stores mappings.
func (h *Handler) hashEnvVars(ctx context.Context, pod *corev1.Pod, podID string) {
	hashedVars := []string{}

	for i := range pod.Spec.Containers {
		container := &pod.Spec.Containers[i]
		if container.Name == "envoy-sidecar" {
			continue
		}

		for j := range container.Env {
			env := &container.Env[j]
			if h.shouldHash(env.Name) && env.Value != "" {
				originalValue := env.Value
				hashedValue := hash.GenerateWithPrefix(originalValue)

				// Store the mapping
				_ = h.storage.Store(ctx, podID, hashedValue, originalValue)

				// Replace value with hash
				env.Value = hashedValue
				hashedVars = append(hashedVars, env.Name)
			}
		}
	}

	// Annotate pod with list of hashed env vars
	if len(hashedVars) > 0 {
		if pod.Annotations == nil {
			pod.Annotations = make(map[string]string)
		}
		pod.Annotations[AnnotationHashedEnvs] = fmt.Sprintf("%v", hashedVars)
	}
}

// shouldHash checks if an env var should be hashed.
func (h *Handler) shouldHash(name string) bool {
	for _, n := range h.envsToHash {
		if n == name {
			return true
		}
	}
	return false
}
