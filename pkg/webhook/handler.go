// Package webhook provides the Kubernetes mutating admission webhook
// for injecting Envoy sidecars and Root CA into pods.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/go-logr/logr"
	"github.com/spinningfactory/kloak/pkg/hash"
	"github.com/spinningfactory/kloak/pkg/storage"
)

const (
	// AnnotationEnabled is the annotation to enable Kloak on a pod.
	AnnotationEnabled = "getkloak.io/enabled"

	// AnnotationHashedEnvs lists env vars that were hashed.
	AnnotationHashedEnvs = "getkloak.io/hashed-envs"

	// EnvoyImage is the default Envoy sidecar image.
	EnvoyImage = "envoyproxy/envoy:v1.37-latest"

	// EnvoyPort is the port Envoy listens on for intercepted traffic.
	EnvoyPort = 15001

	// CACertFile matches the key in the ConfigMap
	CACertFile = "root-ca.crt"

	// CAVolumeName is the name of the volume containing the CA.
	CAVolumeName = "kloak-ca"

	// CAConfigMapName is the name of the ConfigMap containing the CA cert.
	CAConfigMapName = "kloak-ca-cert"
)

// Handler handles pod mutation requests.
type Handler struct {
	client         client.Client
	decoder        admission.Decoder
	storage        storage.Storage
	envsToHash     []string // Environment variable names to hash
	remoteStoreURL string   // URL to Controller Store API
	log            logr.Logger
}

// NewHandler creates a new webhook handler.
func NewHandler(c client.Client, store storage.Storage, envsToHash []string, remoteStoreURL string, log logr.Logger) *Handler {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	return &Handler{
		client:         c,
		storage:        store,
		envsToHash:     envsToHash,
		decoder:        admission.NewDecoder(scheme),
		remoteStoreURL: remoteStoreURL,
		log:            log,
	}
}

// Handle processes admission requests for pods.
func (h *Handler) Handle(ctx context.Context, req admission.Request) admission.Response {
	pod := &corev1.Pod{}
	if err := h.decoder.Decode(req, pod); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	// Check if Kloak is enabled for this pod
	if !h.isEnabled(pod) {
		return admission.Allowed("kloak not enabled")
	}

	// Create a copy to mutate
	mutatedPod := pod.DeepCopy()

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

	// 4. Hash sensitive environment variables
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

// isEnabled checks if Kloak should process this pod.
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

// mountRootCA mounts the CA certificate ConfigMap as a volume.
// Uses ConfigMap volume mount for automatic updates when CA changes.
func (h *Handler) mountRootCA(pod *corev1.Pod) {
	const (
		CAVolName   = "kloak-ca"
		CAVolPath   = "/etc/kloak-ca"
		CACertFile  = "ca.crt" // Key in the ConfigMap
		CAConfigMap = "kloak-ca-cert"
	)

	// 1. Add ConfigMap volume for CA certificate
	// This volume auto-updates when the ConfigMap changes (~60s kubelet sync)
	pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
		Name: CAVolName,
		VolumeSource: corev1.VolumeSource{
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: CAConfigMap,
				},
				Optional: ptr(true), // Don't fail pod if ConfigMap doesn't exist yet
			},
		},
	})

	// 2. Mount volume to all containers and inject env var
	for i := range pod.Spec.Containers {
		pod.Spec.Containers[i].VolumeMounts = append(
			pod.Spec.Containers[i].VolumeMounts,
			corev1.VolumeMount{
				Name:      CAVolName,
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
				entry := storage.Entry{Value: originalValue, AllowedHosts: []string{"*"}}
				_ = h.storage.Store(ctx, podID, hashedValue, entry)

				// Send to Remote Store (Controller)
				if h.remoteStoreURL != "" {
					go h.sendToRemoteStore(hashedValue, originalValue)
				}

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

func (h *Handler) sendToRemoteStore(hash, original string) {
	fmt.Printf("DEBUG: Sending hash %s to %s\n", hash, h.remoteStoreURL)
	if h.remoteStoreURL == "" {
		fmt.Println("DEBUG: Remote URL is empty")
		return
	}

	payload := map[string]interface{}{
		"hash":          hash,
		"original":      original,
		"allowed_hosts": []string{"*"},
	}
	data, _ := json.Marshal(payload)

	// We ignore errors here.
	// Use background context for goroutine
	resp, err := http.Post(h.remoteStoreURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		fmt.Printf("DEBUG: Error sending hash: %v\n", err)
		h.log.Error(err, "failed to send hash to remote store", "url", h.remoteStoreURL)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("DEBUG: Remote store returned status: %s\n", resp.Status)
		h.log.Info("remote store returned non-OK status", "status", resp.Status)
	} else {
		fmt.Printf("DEBUG: Successfully sent hash\n")
		h.log.Info("successfully sent hash to remote store", "hash", hash)
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
