// Package webhook provides the mutating admission webhook handler
// for rewriting secret volumes to point to shadow secrets.
package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	// LabelEnabled is the label used to enable Kloak on a pod or namespace.
	// Pod-level enablement uses a label (not annotation) so that Kubernetes
	// objectSelector can match it, allowing the webhook to be scoped precisely.
	LabelEnabled = "getkloak.io/enabled"

	// AnnotationEnabled is the annotation injected by the webhook onto mutated pods.
	// The controller (DaemonSet) reads this to determine if a pod is kloak-enabled.
	AnnotationEnabled = "getkloak.io/enabled"
)

type Handler struct {
	client  client.Client
	decoder admission.Decoder
	log     *zap.SugaredLogger
}

func NewHandler(c client.Client, log *zap.SugaredLogger) *Handler {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	return &Handler{
		client:  c,
		decoder: admission.NewDecoder(scheme),
		log:     log,
	}
}

// Handle processes admission requests for pods.
// The admission.Handler interface requires req by value — cannot use a pointer.
func (h *Handler) Handle(ctx context.Context, req admission.Request) admission.Response { //nolint:gocritic // hugeParam: interface requirement
	pod := &corev1.Pod{}
	if err := h.decoder.Decode(req, pod); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	// Check if Kloak is enabled for this pod (explicitly or via namespace inheritance)
	enabled, err := h.isEnabled(ctx, pod, req.Namespace)
	if err != nil {
		h.log.Errorw("failed to check if pod is enabled", "error", err)
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

	// Rewrite Secret volumes (swap with shadow secrets)
	if err := h.rewriteSecretVolumes(ctx, mutatedPod, req.Namespace); err != nil {
		h.log.Errorw("shadow secret not ready, rejecting pod", "error", err)
		return admission.Denied(fmt.Sprintf("kloak: %v", err))
	}

	// Create JSON patch
	marshaledPod, err := json.Marshal(mutatedPod)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}

	return admission.PatchResponseFromRaw(req.Object.Raw, marshaledPod)
}

// isEnabled checks if Kloak should process this pod.
// Enablement is determined by pod label or namespace label only.
// Workload-level inheritance (Deployment, DaemonSet, etc.) is not supported;
// use pod template labels or namespace labels instead.
func (h *Handler) isEnabled(ctx context.Context, pod *corev1.Pod, namespace string) (bool, error) {
	// 1. Check pod label
	if pod.Labels != nil {
		if val, ok := pod.Labels[LabelEnabled]; ok {
			return val == "true", nil
		}
	}

	// 2. Check namespace label
	ns := &corev1.Namespace{}
	if err := h.client.Get(ctx, client.ObjectKey{Name: namespace}, ns); err != nil {
		h.log.Errorw("failed to fetch namespace for label check", "error", err, "namespace", namespace)
		return false, err
	}

	if ns.Labels != nil && ns.Labels[LabelEnabled] == "true" {
		return true, nil
	}

	return false, nil
}

// rewriteSecretVolumes checks volume mounts and swaps enabled secrets with shadow secrets.
// Returns an error if a kloak-enabled secret's shadow does not exist (fail closed).
func (h *Handler) rewriteSecretVolumes(ctx context.Context, pod *corev1.Pod, namespace string) error {
	for i := range pod.Spec.Volumes {
		vol := &pod.Spec.Volumes[i]
		if vol.Secret == nil {
			continue
		}

		secretName := vol.Secret.SecretName

		// Resolve namespace
		ns := namespace
		if ns == "" {
			ns = "default"
		}

		// Check if secret is enabled
		var secret corev1.Secret
		if err := h.client.Get(ctx, client.ObjectKey{Name: secretName, Namespace: ns}, &secret); err != nil {
			if client.IgnoreNotFound(err) != nil {
				// API error (permissions, transient failure) -- deny to maintain fail-closed posture
				return fmt.Errorf("failed to look up secret %s/%s: %w", ns, secretName, err)
			}
			// Secret not found -- skip rewriting. Pod admission will fail downstream if it's truly missing.
			h.log.Debugw("secret not found for volume rewriting", "name", secretName)
			continue
		}

		enabled := secret.Labels[LabelEnabled] == "true" || secret.Annotations[LabelEnabled] == "true"
		if !enabled {
			continue
		}

		// Secret is kloak-enabled -- verify shadow exists before rewriting.
		// If the shadow doesn't exist (controller hasn't reconciled yet), reject
		// the pod to prevent mounting real secrets.
		shadowName := secretName + "-kloak"
		var shadowSecret corev1.Secret
		if err := h.client.Get(ctx, client.ObjectKey{Name: shadowName, Namespace: ns}, &shadowSecret); err != nil {
			return fmt.Errorf("shadow secret %s/%s not found for kloak-enabled secret %s (controller may not have reconciled yet)", ns, shadowName, secretName)
		}
		if shadowSecret.Labels["getkloak.io/managed"] != "true" {
			return fmt.Errorf("secret %s/%s exists but is not a kloak-managed shadow secret", ns, shadowName)
		}

		h.log.Debugw("Rewriting volume to use shadow secret", "original", secretName, "shadow", shadowName)
		vol.Secret.SecretName = shadowName
	}

	return nil
}
