// Package webhook provides the mutating admission webhook handler
// for rewriting secret volumes to point to shadow secrets.
package webhook

import (
	"context"
	"encoding/json"
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
)

type Handler struct {
	client  client.Client
	decoder admission.Decoder
	log     logr.Logger
}

func NewHandler(c client.Client, log logr.Logger) *Handler {
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

	// Rewrite Secret volumes (swap with shadow secrets)
	h.rewriteSecretVolumes(ctx, mutatedPod, req.Namespace)

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

// rewriteSecretVolumes checks volume mounts and swaps enabled secrets with shadow secrets.
func (h *Handler) rewriteSecretVolumes(ctx context.Context, pod *corev1.Pod, namespace string) {
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
}
