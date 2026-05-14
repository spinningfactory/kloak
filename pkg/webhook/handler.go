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
		h.log.Errorw("shadow secret not ready for volume, rejecting pod", "error", err)
		return admission.Denied(fmt.Sprintf("kloak: %v", err))
	}

	// Rewrite Secret env var references (secretKeyRef + envFrom secretRef)
	// in every Container and InitContainer. Same fail-closed semantics as
	// volumes: kloak-enabled secret with no valid shadow → admission denied.
	if err := h.rewriteSecretEnvVars(ctx, mutatedPod, req.Namespace); err != nil {
		h.log.Errorw("shadow secret not ready for env var, rejecting pod", "error", err)
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

// rewriteSecretVolumes swaps Secret volume mounts that point at kloak-enabled
// secrets with their shadow counterparts. Returns an error if a kloak-enabled
// secret has no valid shadow (fail closed — controller may not have reconciled
// yet, or someone deleted the shadow by hand).
func (h *Handler) rewriteSecretVolumes(ctx context.Context, pod *corev1.Pod, namespace string) error {
	for i := range pod.Spec.Volumes {
		vol := &pod.Spec.Volumes[i]
		if vol.Secret == nil {
			continue
		}
		optional := vol.Secret.Optional != nil && *vol.Secret.Optional
		ok, shadow, err := h.lookupKloakSecret(ctx, vol.Secret.SecretName, namespace, optional)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		h.log.Debugw("rewriting volume to use shadow secret",
			"original", vol.Secret.SecretName, "shadow", shadow)
		vol.Secret.SecretName = shadow
	}
	return nil
}

// rewriteSecretEnvVars rewrites secretKeyRef + envFrom secretRef
// references across every Container, InitContainer, AND EphemeralContainer
// to point at the shadow secret. Same fail-closed semantics as
// rewriteSecretVolumes.
//
// Env / EnvFrom are container-level fields, so all three container slices
// must be iterated separately — unlike Spec.Volumes which is pod-level
// and shared. EphemeralContainers carry their fields under the embedded
// EphemeralContainerCommon struct (same shape as Container), so the inner
// helper is factored to take the slices directly rather than a
// *corev1.Container.
//
// Note: kloak's MutatingWebhookConfiguration is scoped to pod CREATE
// today; the `ephemeralcontainers` subresource (used by `kubectl debug`)
// doesn't trigger this webhook. The EphemeralContainers loop is defensive
// coverage for pods that pre-declare ephemeral containers at create time,
// and so the helper stays correct if the webhook scope ever widens.
func (h *Handler) rewriteSecretEnvVars(ctx context.Context, pod *corev1.Pod, namespace string) error {
	for i := range pod.Spec.Containers {
		c := &pod.Spec.Containers[i]
		if err := h.rewriteEnvSlices(ctx, c.Name, c.Env, c.EnvFrom, namespace); err != nil {
			return err
		}
	}
	for i := range pod.Spec.InitContainers {
		c := &pod.Spec.InitContainers[i]
		if err := h.rewriteEnvSlices(ctx, c.Name, c.Env, c.EnvFrom, namespace); err != nil {
			return err
		}
	}
	for i := range pod.Spec.EphemeralContainers {
		ec := &pod.Spec.EphemeralContainers[i]
		if err := h.rewriteEnvSlices(ctx, ec.Name, ec.Env, ec.EnvFrom, namespace); err != nil {
			return err
		}
	}
	return nil
}

// rewriteEnvSlices is the inner per-container logic. Takes slices
// directly so it can work for Container, InitContainer (both
// corev1.Container) AND EphemeralContainer (whose Env/EnvFrom fields
// live on the embedded EphemeralContainerCommon, not directly on a
// *corev1.Container). Modifications happen via the pointer-typed
// ValueFrom / SecretRef fields, so the slice itself doesn't need to
// be a pointer.
func (h *Handler) rewriteEnvSlices(ctx context.Context, containerName string, env []corev1.EnvVar, envFrom []corev1.EnvFromSource, namespace string) error {
	// env[].valueFrom.secretKeyRef — single key from a secret.
	for i := range env {
		vf := env[i].ValueFrom
		if vf == nil || vf.SecretKeyRef == nil {
			continue
		}
		optional := vf.SecretKeyRef.Optional != nil && *vf.SecretKeyRef.Optional
		ok, shadow, err := h.lookupKloakSecret(ctx, vf.SecretKeyRef.Name, namespace, optional)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		h.log.Debugw("rewriting env secretKeyRef to use shadow secret",
			"container", containerName, "envVar", env[i].Name,
			"original", vf.SecretKeyRef.Name, "shadow", shadow)
		vf.SecretKeyRef.Name = shadow
	}

	// envFrom[].secretRef — every key from a secret.
	for i := range envFrom {
		sr := envFrom[i].SecretRef
		if sr == nil {
			continue
		}
		optional := sr.Optional != nil && *sr.Optional
		ok, shadow, err := h.lookupKloakSecret(ctx, sr.Name, namespace, optional)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		h.log.Debugw("rewriting envFrom secretRef to use shadow secret",
			"container", containerName, "original", sr.Name, "shadow", shadow)
		sr.Name = shadow
	}
	return nil
}

// lookupKloakSecret resolves a secret reference and decides whether it should
// be rewritten to its shadow.
//
//	ok == true:  caller should rewrite the reference to `shadow`. The
//	             secret carries the kloak-enabled label/annotation AND
//	             its `<name>-kloak` shadow exists and is kloak-managed.
//	ok == false, err == nil: leave the reference alone. The secret either
//	             doesn't exist (admission will fail downstream for required
//	             refs; Kubernetes silently no-ops for `optional: true`),
//	             or it exists but isn't kloak-enabled.
//	err != nil:  fail-closed denial. Either an API error (permissions,
//	             transient failure) or a kloak-enabled secret whose
//	             shadow is missing / malformed.
//
// Empty namespace falls back to "default" — same convention as the rest of
// the webhook for unnamespaced admission requests.
func (h *Handler) lookupKloakSecret(ctx context.Context, name, namespace string, optional bool) (ok bool, shadow string, err error) {
	if name == "" {
		return false, "", nil
	}
	ns := namespace
	if ns == "" {
		ns = "default"
	}

	var secret corev1.Secret
	if err := h.client.Get(ctx, client.ObjectKey{Name: name, Namespace: ns}, &secret); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return false, "", fmt.Errorf("failed to look up secret %s/%s: %w", ns, name, err)
		}
		h.log.Debugw("secret not found, leaving reference alone",
			"name", name, "namespace", ns, "optional", optional)
		return false, "", nil
	}

	enabled := secret.Labels[LabelEnabled] == "true" || secret.Annotations[LabelEnabled] == "true"
	if !enabled {
		return false, "", nil
	}

	shadowName := name + "-kloak"
	var shadowSecret corev1.Secret
	if err := h.client.Get(ctx, client.ObjectKey{Name: shadowName, Namespace: ns}, &shadowSecret); err != nil {
		return false, "", fmt.Errorf("shadow secret %s/%s not found for kloak-enabled secret %s (controller may not have reconciled yet)", ns, shadowName, name)
	}
	if shadowSecret.Labels["getkloak.io/managed"] != "true" {
		return false, "", fmt.Errorf("secret %s/%s exists but is not a kloak-managed shadow secret", ns, shadowName)
	}
	return true, shadowName, nil
}
