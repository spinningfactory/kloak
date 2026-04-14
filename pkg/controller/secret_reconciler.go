package controller

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/sys/unix"
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

	// AnnotationPort is the label/annotation to specify an allowed port for a secret.
	AnnotationPort = "getkloak.io/port"

	// AnnotationHosts is the label/annotation to specify allowed hosts for a secret.
	AnnotationHosts = "getkloak.io/hosts"

	// ShadowSecretSuffix is the suffix appended to the name of the shadow secret.
	ShadowSecretSuffix = "-kloak"

	// ValuePrefix is the prefix for generated UUID values.
	// Must match what the eBPF program expects.
	ValuePrefix = "kloak:"

	// ShadowPrefixLen is the length of the prefix used for BPF map key collision detection.
	// The BPF program uses the first 8 bytes as the lookup key.
	ShadowPrefixLen = 8
)

type PortSpec struct {
	Port     uint16
	Protocol uint8
}

func parsePortSpec(spec string) (PortSpec, error) {
	spec = strings.TrimSpace(spec)
	spec = strings.ToLower(spec)

	protoStr := "tcp"
	parts := strings.Split(spec, "/")
	if len(parts) == 0 || len(parts) > 2 {
		return PortSpec{}, fmt.Errorf("invalid port format: %s", spec)
	} else if len(parts) == 2 {
		protoStr = parts[1]
	}
	portStr := parts[0]

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return PortSpec{}, err
	} else if port == 0 || port > 65535 {
		return PortSpec{}, fmt.Errorf("invalid port: %d", port)
	}

	var proto uint8
	switch protoStr {
	case "tcp":
		proto = uint8(unix.IPPROTO_TCP)
	case "udp":
		proto = uint8(unix.IPPROTO_UDP)
	default:
		return PortSpec{}, fmt.Errorf("invalid proto: %s", protoStr)
	}

	return PortSpec{Port: uint16(port), Protocol: proto}, nil
}

// SecretReconciler reconciles a Secret object
type SecretReconciler struct {
	client.Client
	Log     *zap.SugaredLogger
	Scheme  *runtime.Scheme
	Storage storage.Storage
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
		// We also need to clean up Storage mappings.
		// We use the Secret ID as the storage "podID" bucket.
		secretID := fmt.Sprintf("%s/%s", secret.Namespace, secret.Name)
		if err := r.Storage.Delete(ctx, secretID); err != nil {
			log.Errorw("failed to clean up storage mappings", "error", err)
		}
		return ctrl.Result{}, nil
	}

	// 4. Reconcile Shadow Secret
	log.Infow("Reconciling enabled secret")

	// Validate secret length: eBPF requires at least ShadowPrefixLen bytes for the BPF key lookup
	// Short secrets cannot be processed correctly by eBPF and are not supported
	for key, originalBytes := range secret.Data {
		originalLen := len(originalBytes)
		if originalLen < ShadowPrefixLen {
			log.Info("Skipping secret with value too short for eBPF (minimum ShadowPrefixLen bytes required)",
				"secret", req.String(),
				"key", key,
				"length", originalLen,
				"minimumRequired", ShadowPrefixLen)
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

	// Recalculate all mappings, then clear old ones and store the new ones.
	// Delete-before-store removes stale keys (e.g. a key removed from the original secret)
	// while ULIDs are reused where possible to keep shadow values stable.

	// Fetch all existing shadows from storage once for collision detection
	// This avoids O(N×M) complexity from calling List() for each key
	allEntries, err := r.Storage.List(ctx)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to list storage: %w", err)
	}

	// Build a map of existing shadow prefixes to detect collisions with other secrets
	// Key: 8-byte prefix, Value: set of ownerIDs that use this prefix
	existingPrefixMap := make(map[string]map[string]struct{})
	for shadow := range allEntries {
		if len(shadow) >= ShadowPrefixLen {
			prefix := shadow[:ShadowPrefixLen]
			ownerID, found, _ := r.Storage.GetOwnerID(ctx, shadow)
			if found {
				if existingPrefixMap[prefix] == nil {
					existingPrefixMap[prefix] = make(map[string]struct{})
				}
				existingPrefixMap[prefix][ownerID] = struct{}{}
			}
		}
	}

	// Track all shadows in this batch to detect intra-secret collisions
	var shadowsInBatch []string
	newMappings := make(map[string]string) // shadow -> original

	for key, originalBytes := range secret.Data {
		originalValue := string(originalBytes)
		originalLen := len(originalBytes)
		var shadowValue string

		// Try to reuse existing UUID
		if shadowExists && len(existingShadow.Data[key]) > 0 {
			existingVal := string(existingShadow.Data[key])
			if strings.HasPrefix(existingVal, ValuePrefix) {
				// Check if existing shadow collides with other secrets
				// Pass secretID to exclude shadows from the current secret
				if len(existingVal) == originalLen {
					if !checkCollisionsWithMap(existingVal, secretID, existingPrefixMap) {
						// Check it doesn't collide with other keys in this same secret
						if prefix := existingVal[:ShadowPrefixLen]; !isPrefixUsed(shadowsInBatch, prefix) {
							shadowValue = existingVal
						}
					}
				}
			}
		}

		// Generate new if needed or if length mismatch or collision detected
		if shadowValue == "" {
			var err error
			shadowValue, err = r.generateShadowValueWithCollisionCheck(
				originalLen, originalValue, secretID, 3, existingPrefixMap,
			)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("failed to generate shadow value for key %s: %w", key, err)
			}
		}

		// Track this shadow to detect collisions with other keys in same secret
		shadowsInBatch = append(shadowsInBatch, shadowValue)
		newData[key] = []byte(shadowValue)
		newMappings[shadowValue] = originalValue
	}

	// Update Storage
	// We delete first to remove stale keys (keys removed from original secret)
	if err := r.Storage.Delete(ctx, secretID); err != nil {
		log.Errorw("failed to clear old storage mappings", "error", err)
	}

	for shadowVal, originalVal := range newMappings {
		// Parse allowed hosts
		allowedHosts := []string{"*"}
		if hostsLabel, ok := secret.Labels[AnnotationHosts]; ok && hostsLabel != "" {
			// Split by comma and trim spaces
			parts := strings.Split(hostsLabel, ",")
			allowedHosts = make([]string, 0, len(parts))
			for _, p := range parts {
				if trimmed := strings.TrimSpace(p); trimmed != "" {
					allowedHosts = append(allowedHosts, trimmed)
				}
			}
		}

		var portSpec PortSpec
		var err error
		validPort := false
		if v, ok := secret.Labels[AnnotationPort]; ok && v != "" {
			portSpec, err = parsePortSpec(v)
			if err != nil {
				log.Errorw("Invalid port specification, treating as wildcard", "error", err, "secret", req.NamespacedName, "label", v)
			} else {
				validPort = true
			}
		}

		entry := storage.Entry{
			Value:        originalVal,
			AllowedHosts: allowedHosts,
		}
		if validPort {
			entry.Port = portSpec.Port
			entry.Protocol = portSpec.Protocol
		}
		if err := r.Storage.Store(ctx, secretID, shadowVal, entry); err != nil {
			log.Errorw("failed to store mapping", "error", err, "shadow", shadowVal)
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
		log.Infow("Updated shadow secret", "name", shadowName)
	} else {
		if err := r.Create(ctx, shadowSecret); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to create shadow secret: %w", err)
		}
		log.Infow("Created shadow secret", "name", shadowName)
	}

	return ctrl.Result{}, nil
}

// checkCollisionsWithMap checks if a shadow value's 8-byte BPF prefix collides with any existing
// shadow values in the provided prefix map (excluding shadows from the current secret being reconciled).
// Returns true if a collision is detected.
func checkCollisionsWithMap(newShadow, excludeSecretID string, existingPrefixMap map[string]map[string]struct{}) bool {
	newPrefix := newShadow[:ShadowPrefixLen]

	// Check if this prefix is used by other secrets
	if owners, exists := existingPrefixMap[newPrefix]; exists {
		for ownerID := range owners {
			if ownerID != excludeSecretID {
				// Collision with a different secret
				return true
			}
		}
	}

	return false
}

// generateShadowValueWithCollisionCheck creates a shadow value and ensures no 8-byte prefix collision
// with existing secrets (excluding shadows from the current secret being reconciled).
// It retries generation up to maxRetries times if collisions are detected.
func (r *SecretReconciler) generateShadowValueWithCollisionCheck(
	originalLen int,
	realSecret string,
	excludeSecretID string,
	maxRetries int,
	existingPrefixMap map[string]map[string]struct{},
) (string, error) {
	for attempt := 0; attempt < maxRetries; attempt++ {
		shadow := generateShadowValue(originalLen, realSecret)

		if checkCollisionsWithMap(shadow, excludeSecretID, existingPrefixMap) {
			r.Log.V(2).Info("8-byte BPF key collision detected, regenerating",
				"attempt", attempt+1, "maxRetries", maxRetries,
				"prefix", shadow[:ShadowPrefixLen])
			continue
		}

		return shadow, nil
	}

	return "", fmt.Errorf("failed to generate unique shadow value after %d attempts", maxRetries)
}

// isPrefixUsed checks if a prefix is already used in the given shadows.
func isPrefixUsed(shadows []string, prefix string) bool {
	for _, shadow := range shadows {
		if len(shadow) >= ShadowPrefixLen && shadow[:ShadowPrefixLen] == prefix {
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
