package k8s

import (
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/spinningfactory/kloak/pkg/secrets"
)

// PodSecretRefs returns the kloak secrets a pod references in its spec,
// which are the only secrets the data plane will rewrite for that pod.
//
// A reference is a shadow Secret (`<name>-kloak`, as written by the
// mutating webhook) used through a Secret volume, a projected Secret
// source, an env `secretKeyRef` or an `envFrom` `secretRef`, in any
// container or init container. Volumes and projected sources with `items`
// and `secretKeyRef` narrow the reference to those keys; everything else
// grants every key of the secret. Ephemeral containers are not considered:
// the controller does not track their cgroups.
//
// Pods can only reference Secrets in their own namespace, so every Ref is
// scoped to the pod's namespace. The result is sorted by OwnerID with
// sorted keys.
func PodSecretRefs(pod *corev1.Pod) []secrets.Ref {
	// owner → set of keys; a nil set means every key.
	keys := make(map[string]map[string]struct{})
	add := func(shadowName string, items []string) {
		owner, ok := shadowOwner(pod.Namespace, shadowName)
		if !ok {
			return
		}
		set, seen := keys[owner]
		if seen && set == nil {
			return // already grants every key
		}
		if len(items) == 0 {
			keys[owner] = nil
			return
		}
		if set == nil {
			set = make(map[string]struct{}, len(items))
			keys[owner] = set
		}
		for _, k := range items {
			set[k] = struct{}{}
		}
	}

	for i := range pod.Spec.Volumes {
		vol := &pod.Spec.Volumes[i]
		if vol.Secret != nil {
			add(vol.Secret.SecretName, keyToPathKeys(vol.Secret.Items))
		}
		if vol.Projected != nil {
			for _, src := range vol.Projected.Sources {
				if src.Secret != nil {
					add(src.Secret.Name, keyToPathKeys(src.Secret.Items))
				}
			}
		}
	}

	containers := make([]*corev1.Container, 0, len(pod.Spec.InitContainers)+len(pod.Spec.Containers))
	for i := range pod.Spec.InitContainers {
		containers = append(containers, &pod.Spec.InitContainers[i])
	}
	for i := range pod.Spec.Containers {
		containers = append(containers, &pod.Spec.Containers[i])
	}
	for _, c := range containers {
		for _, env := range c.Env {
			if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
				add(env.ValueFrom.SecretKeyRef.Name, []string{env.ValueFrom.SecretKeyRef.Key})
			}
		}
		for _, src := range c.EnvFrom {
			if src.SecretRef != nil {
				add(src.SecretRef.Name, nil)
			}
		}
	}

	refs := make([]secrets.Ref, 0, len(keys))
	for owner, set := range keys {
		ref := secrets.Ref{OwnerID: owner}
		if set != nil {
			ref.Keys = make([]string, 0, len(set))
			for k := range set {
				ref.Keys = append(ref.Keys, k)
			}
			sort.Strings(ref.Keys)
		}
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].OwnerID < refs[j].OwnerID })
	return refs
}

// shadowOwner maps a referenced Secret name to the OwnerID of the secret it
// shadows. Only shadow names carry kloak secrets; anything else is a plain
// Secret the data plane never rewrites.
func shadowOwner(namespace, name string) (string, bool) {
	original, ok := strings.CutSuffix(name, ShadowSecretSuffix)
	if !ok || original == "" {
		return "", false
	}
	return namespace + "/" + original, true
}

func keyToPathKeys(items []corev1.KeyToPath) []string {
	if len(items) == 0 {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.Key)
	}
	return out
}
