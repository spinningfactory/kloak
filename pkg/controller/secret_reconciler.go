package controller

import (
	"context"
	"fmt"
	"strings"

	"crypto/rand"
	"math/big"
	"time"

	"github.com/go-logr/logr"
	"github.com/oklog/ulid/v2"
	"golang.org/x/net/http2/hpack"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/spinningfactory/kloak/pkg/storage"
)

const (
	// AnnotationSecretEnabled is the label/annotation to enable Kloak secret replication.
	AnnotationSecretEnabled = "getkloak.io/enabled"

	// ShadowSecretSuffix is the suffix appended to the name of the shadow secret.
	ShadowSecretSuffix = "-kloak"

	// ValuePrefix is the prefix for generated UUID values.
	// Must match what the eBPF program expects.
	ValuePrefix = "kloak:"
)

// SecretReconciler reconciles a Secret object
type SecretReconciler struct {
	client.Client
	Log     logr.Logger
	Scheme  *runtime.Scheme
	Storage storage.Storage
}

// Reconcile handles Secret events.
func (r *SecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("secret", req.NamespacedName)

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
				log.Info("Deleting disabled shadow secret", "shadow", shadowName)
				if err := r.Delete(ctx, &shadowSecret); err != nil {
					return ctrl.Result{}, fmt.Errorf("failed to delete shadow secret: %w", err)
				}
			}
		}
		// We also need to clean up Storage mappings.
		// We use the Secret ID as the storage "podID" bucket.
		secretID := fmt.Sprintf("%s/%s", secret.Namespace, secret.Name)
		if err := r.Storage.Delete(ctx, secretID); err != nil {
			log.Error(err, "failed to clean up storage mappings")
		}
		return ctrl.Result{}, nil
	}

	// 4. Reconcile Shadow Secret
	log.Info("Reconciling enabled secret")

	// Fetch existing shadow secret to preserve UUIDs if possible
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

	// Recalculate all mappings, then clear old ones and store the new ones.
	// Delete-before-store removes stale keys (e.g. a key removed from the original secret)
	// while UUIDs are reused where possible to keep shadow values stable.

	newMappings := make(map[string]string) // uuid -> original

	for key, originalBytes := range secret.Data {
		originalValue := string(originalBytes)
		originalLen := len(originalBytes)
		var shadowValue string

		// Try to reuse existing UUID
		if shadowExists && len(existingShadow.Data[key]) > 0 {
			existingVal := string(existingShadow.Data[key])
			if strings.HasPrefix(existingVal, ValuePrefix) {
				// Strip padding if necessary to compare/reuse the true UUID part
				// For now, let's just use the exact existing padded string if lengths match
				if len(existingVal) == originalLen {
					shadowValue = existingVal
				}
			}
		}

		// Generate new if needed or if length mismatch
		if shadowValue == "" {
			shadowValue = generateShadowValue(originalLen, originalValue)
		}

		newData[key] = []byte(shadowValue)
		newMappings[shadowValue] = originalValue
	}

	// Update Storage
	// We delete first to remove stale keys (keys removed from original secret)
	if err := r.Storage.Delete(ctx, secretID); err != nil {
		log.Error(err, "failed to clear old storage mappings")
	}

	for shadowVal, originalVal := range newMappings {
		// Parse allowed hosts
		allowedHosts := []string{"*"}
		if hostsLabel, ok := secret.Labels["getkloak.io/hosts"]; ok && hostsLabel != "" {
			// Split by comma and trim spaces
			parts := strings.Split(hostsLabel, ",")
			allowedHosts = make([]string, 0, len(parts))
			for _, p := range parts {
				if trimmed := strings.TrimSpace(p); trimmed != "" {
					allowedHosts = append(allowedHosts, trimmed)
				}
			}
		}

		// Store mapping (uuid -> original + hosts)
		entry := storage.Entry{
			Value:        originalVal,
			AllowedHosts: allowedHosts,
		}
		if err := r.Storage.Store(ctx, secretID, shadowVal, entry); err != nil {
			log.Error(err, "failed to store mapping", "shadow", shadowVal)
			return ctrl.Result{}, err
		}
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
		log.Info("Updated shadow secret", "name", shadowName)
	} else {
		if err := r.Create(ctx, shadowSecret); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to create shadow secret: %w", err)
		}
		log.Info("Created shadow secret", "name", shadowName)
	}

	return ctrl.Result{}, nil
}

func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		Complete(r)
}

func ptr[T any](v T) *T {
	return &v
}

// generateShadowValue creates a shadow value of exactly originalLen bytes
// whose HPACK Huffman encoding is at least as long as the real secret's.
// This ensures HTTP/2 HPACK rewriting works — the shadow's Huffman length
// determines the space available in the wire buffer for the rewritten value.
func generateShadowValue(originalLen int, realSecret string) string {
	realHuffLen := int(hpack.HuffmanEncodeLength(realSecret))

	// ULID uses Crockford Base32 (uppercase + digits, no hyphens).
	// These chars have long HPACK Huffman codes (7-8 bits), naturally
	// producing longer Huffman encodings than UUID hex (5-6 bits).
	// "kloak:" (6) + ULID (26) = 32 chars total.
	// ULID format: 10 chars timestamp + 16 chars random. For short secrets,
	// truncation would keep only the timestamp (identical for secrets created
	// at the same time). Put the random part first to maximize uniqueness.
	newULID := ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()
	ulidRandom := newULID[10:] + newULID[:10] // random first, then timestamp
	baseVal := ValuePrefix + ulidRandom

	var shadow string
	switch {
	case len(baseVal) > originalLen:
		shadow = baseVal[:originalLen]
	case len(baseVal) < originalLen:
		// Pad with random Crockford Base32 chars (same charset as ULID)
		const base32Chars = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
		padLen := originalLen - len(baseVal)
		padding := make([]byte, padLen)
		for i := range padding {
			n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(base32Chars))))
			padding[i] = base32Chars[n.Int64()]
		}
		shadow = baseVal + string(padding)
	default:
		shadow = baseVal
	}

	// Verify Huffman length is sufficient for HTTP/2 HPACK rewriting.
	// ULID's uppercase chars usually produce long enough Huffman, but for
	// rare cases (short secrets with all-uppercase real values), replace
	// trailing digits with random uppercase letters (longer Huffman codes).
	shadowHuffLen := int(hpack.HuffmanEncodeLength(shadow))
	if shadowHuffLen < realHuffLen {
		shadowBytes := []byte(shadow)
		for j := len(shadowBytes) - 1; j >= 8 && shadowHuffLen < realHuffLen; j-- {
			if shadowBytes[j] >= '0' && shadowBytes[j] <= '9' {
				n, _ := rand.Int(rand.Reader, big.NewInt(26))
				shadowBytes[j] = byte('A') + byte(n.Int64())
				shadowHuffLen = int(hpack.HuffmanEncodeLength(string(shadowBytes)))
			}
		}
		shadow = string(shadowBytes)
	}

	return shadow
}
