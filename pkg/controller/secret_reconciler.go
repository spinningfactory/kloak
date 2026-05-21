package controller

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/spinningfactory/kloak/pkg/secrets"
	k8ssecrets "github.com/spinningfactory/kloak/pkg/secrets/k8s"
)

const (
	// AnnotationSecretEnabled is the label/annotation to enable Kloak secret replication.
	AnnotationSecretEnabled = "getkloak.io/enabled"

	// AnnotationPort is the annotation to specify an allowed port for a secret.
	AnnotationPort = "getkloak.io/port"

	// AnnotationHosts is the annotation to specify allowed hosts for a secret.
	AnnotationHosts = "getkloak.io/hosts"

	// ShadowSecretSuffix is the suffix appended to the name of the shadow secret.
	ShadowSecretSuffix = "-kloak"
)

// SecretReconciler reconciles a Secret object
type SecretReconciler struct {
	client.Client
	Log    *zap.SugaredLogger
	Scheme *runtime.Scheme
}

// Reconcile handles Secret events.
func (r *SecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.With("secret", req.NamespacedName)

	var secret corev1.Secret
	if err := r.Get(ctx, req.NamespacedName, &secret); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// 1. Check if secret is enabled
	// We support checking both Labels and Annotations for flexibility
	enabled := secret.Labels[AnnotationSecretEnabled] == "true" || secret.Annotations[AnnotationSecretEnabled] == "true"

	// 2. Identify Shadow Secret Name
	shadowName := secret.Name + ShadowSecretSuffix
	shadowNamespacedName := types.NamespacedName{
		Name:      shadowName,
		Namespace: secret.Namespace,
	}

	// 3. Handle deletion or disabled state
	if !secret.DeletionTimestamp.IsZero() || !enabled {
		// If disabled or deleted, we should clean up the shadow secret.
		// We rely on K8s Garbage Collection (OwnerReference) for shadow secret deletion if owner is deleted.
		// But if just disabled, we should delete it manually.
		if !enabled {
			var shadowSecret corev1.Secret
			if err := r.Get(ctx, shadowNamespacedName, &shadowSecret); err == nil {
				log.Infow("Deleting disabled shadow secret", "shadow", shadowName)
				if err := r.Delete(ctx, &shadowSecret); err != nil {
					return ctrl.Result{}, fmt.Errorf("failed to delete shadow secret: %w", err)
				}
			}
		}
		return ctrl.Result{}, nil
	}

	// 4. Reconcile Shadow Secret
	log.Infow("Reconciling enabled secret")

	// Validate secret length: eBPF requires at least secrets.ShadowPrefixLen bytes
	// for the BPF key lookup. Short secrets cannot be processed correctly by eBPF
	// and are not supported.
	for key, originalBytes := range secret.Data {
		originalLen := len(originalBytes)
		if originalLen < secrets.ShadowPrefixLen {
			log.Info("Skipping secret with value too short for eBPF (minimum ShadowPrefixLen bytes required)",
				"secret", req.String(),
				"key", key,
				"length", originalLen,
				"minimumRequired", secrets.ShadowPrefixLen)
			// Return early without creating shadow secret
			return ctrl.Result{}, nil
		}
	}

	// Fetch existing shadow secret to preserve ULIDs if possible
	var existingShadow corev1.Secret
	shadowExists := false
	if err := r.Get(ctx, shadowNamespacedName, &existingShadow); err == nil {
		shadowExists = true
	} else if !errors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("failed to get shadow secret: %w", err)
	}

	// Prepare new data
	newData := make(map[string][]byte)
	secretID := fmt.Sprintf("%s/%s", secret.Namespace, secret.Name)

	// Seed a ShadowGenerator from every shadow currently persisted in the
	// cluster, so freshly-minted shadows do not collide with anything held
	// by another secret. The generator excludes secretID from the
	// collision check, so re-reconciling our own shadow under a stable
	// ULID is not flagged as a self-collision.
	seed, err := k8ssecrets.SeedShadowGenerator(ctx, r.Client)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("seed shadow generator: %w", err)
	}
	gen := secrets.NewShadowGenerator(seed, log)

	// Track shadows already chosen within THIS Reconcile to detect
	// intra-secret collisions across data keys. The generator's
	// cross-owner check excludes secretID, so it would not catch the
	// case where two keys of the same Secret happen onto the same
	// 8-byte prefix.
	var shadowsInBatch []string

	for key, originalBytes := range secret.Data {
		originalValue := string(originalBytes)
		originalLen := len(originalBytes)
		var shadowValue string

		// Try to reuse existing UUID
		if shadowExists && len(existingShadow.Data[key]) > 0 {
			existingVal := string(existingShadow.Data[key])
			if strings.HasPrefix(existingVal, secrets.ValuePrefix) {
				if len(existingVal) == originalLen {
					if !gen.Collides(existingVal, secretID) {
						// Check it doesn't collide with other keys in this same secret
						if prefix := existingVal[:secrets.ShadowPrefixLen]; !isPrefixUsed(shadowsInBatch, prefix) {
							shadowValue = existingVal
							// Record so subsequent gen.Generate within
							// this Reconcile sees this prefix as taken.
							gen.Record(shadowValue, secretID)
						}
					}
				}
			}
		}

		// Generate new if needed or if length mismatch or collision detected.
		// Generate is strict (avoids every occupied prefix, including ones
		// recorded above for prior keys of THIS secret) and auto-records on
		// success.
		if shadowValue == "" {
			var err error
			// Pass the Huffman bit count, not the cleartext: the
			// generator only needs the bit-exact length target to
			// construct a shadow that won't trigger HPACK over-padding,
			// and keeping the real value out of pkg/secrets's scope
			// prevents any future logging/error path there from
			// accidentally surfacing the cleartext.
			shadowValue, err = gen.Generate(originalLen, secrets.HuffmanBits(originalValue), secretID, 3)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to generate shadow value for key %s: %w", key, err)
			}
		}

		// Track this shadow to detect collisions with other keys in same secret
		shadowsInBatch = append(shadowsInBatch, shadowValue)
		newData[key] = []byte(shadowValue)
	}

	// Create or Update Shadow Secret
	shadowSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      shadowName,
			Namespace: secret.Namespace,
			Labels: map[string]string{
				"getkloak.io/managed": "true",
				"getkloak.io/owner":   secret.Name,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         "v1",
					Kind:               "Secret",
					Name:               secret.Name,
					UID:                secret.UID,
					Controller:         ptr(true),
					BlockOwnerDeletion: ptr(true),
				},
			},
		},
		Type: secret.Type, // Preserve type (e.g., Opaque)
		Data: newData,
	}

	if shadowExists {
		existingShadow.Data = newData
		// Ensure ownership is set (in case it was created manually or missing)
		existingShadow.OwnerReferences = shadowSecret.OwnerReferences
		existingShadow.Labels = shadowSecret.Labels
		if err := r.Update(ctx, &existingShadow); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update shadow secret: %w", err)
		}
		log.Infow("Updated shadow secret", "name", shadowName)
	} else {
		if err := r.Create(ctx, shadowSecret); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to create shadow secret: %w", err)
		}
		log.Infow("Created shadow secret", "name", shadowName)
	}

	return ctrl.Result{}, nil
}

// isPrefixUsed checks if a prefix is already used in the given shadows.
// Used by Reconcile to detect intra-secret collisions across data keys —
// the cross-owner ShadowGenerator excludes the current secret's owner
// ID from its check, so a same-secret prefix reuse would not be caught
// by Collides alone.
func isPrefixUsed(shadows []string, prefix string) bool {
	for _, shadow := range shadows {
		if len(shadow) >= secrets.ShadowPrefixLen && shadow[:secrets.ShadowPrefixLen] == prefix {
			return true
		}
	}
	return false
}

func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		Complete(r)
}

func ptr[T any](v T) *T {
	return &v
}
