// Package webhook provides the Kubernetes mutating admission webhook
// for injecting Envoy sidecars and Root CA into pods.
package webhook

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

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

	// JavaInitContainerImage is the image used for the init container when Java is detected.
	JavaInitContainerImage = "eclipse-temurin:21-jre-alpine"

	// JavaTruststoreFile is the filename for the Java truststore.
	JavaTruststoreFile = "truststore.jks"

	// JavaTruststorePassword is the default password for the Java truststore.
	JavaTruststorePassword = "changeit"

	// AnnotationRuntime is the annotation to override runtime detection.
	AnnotationRuntime = "getkloak.io/runtime"
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

	// Fetch CA Cert
	caCert, err := h.getCA(ctx)
	if err != nil {
		h.log.Error(err, "failed to fetch CA certificate")
		// We can't proceed without CA as init container needs it
		// Fail open or closed? Closed seems safer for mesh.
		return admission.Errored(http.StatusInternalServerError, err)
	}

	// Detect Java runtime for truststore handling and Envoy injection
	isJava := needsJavaTruststore(mutatedPod)

	if isJava {
		// 1. Inject Init Container (sets up CA and Envoy config)
		h.injectInitContainer(mutatedPod, caCert)

		// 2. Inject Envoy sidecar
		h.injectEnvoySidecar(mutatedPod)

		// 3. Mount Root CA volume to application containers
		h.mountCAVolume(mutatedPod)
	}

	// 4. Rewrite Secret volumes (swap with shadow secrets)
	if err := h.rewriteSecretVolumes(ctx, mutatedPod, req.Namespace); err != nil {
		h.log.Error(err, "failed to rewrite secret volumes")
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

//go:embed envoy.yaml
var envoyConfig []byte

// getCA fetches the CA certificate from the Kubernetes Secret.
func (h *Handler) getCA(ctx context.Context) (string, error) {
	secret := &corev1.Secret{}
	err := h.client.Get(ctx, client.ObjectKey{
		Namespace: h.systemNamespace,
		Name:      CASecretName,
	}, secret)
	if err != nil {
		return "", err
	}

	if data, ok := secret.Data[corev1.TLSCertKey]; ok {
		return string(data), nil
	} else if data, ok := secret.Data["ca.crt"]; ok {
		return string(data), nil
	}
	return "", fmt.Errorf("CA secret missing certificate key")
}

// javaImagePatterns are substrings that indicate a Java-based container image.
var javaImagePatterns = []string{
	"java", "jdk", "jre", "temurin", "openjdk", "corretto",
	"spring-boot", "quarkus", "graalvm",
}

// needsJavaTruststore returns true if the pod requires Java truststore setup.
// It checks for an explicit annotation override first, then scans container images
// for known Java-related patterns.
func needsJavaTruststore(pod *corev1.Pod) bool {
	// Check annotation override
	if pod.Annotations != nil {
		if val, ok := pod.Annotations[AnnotationRuntime]; ok {
			return val == "java"
		}
	}

	// Scan container images for Java patterns
	for _, c := range pod.Spec.Containers {
		image := strings.ToLower(c.Image)
		for _, pattern := range javaImagePatterns {
			if strings.Contains(image, pattern) {
				return true
			}
		}
	}
	return false
}

// injectInitContainer injects the Kloak init container which sets up CA and Envoy config.
func (h *Handler) injectInitContainer(pod *corev1.Pod, caCert string) {
	const (
		EnvoyConfigVolName = "kloak-envoy-config-vol"
		CAVolName          = "kloak-ca-vol"
	)

	// Always add the CA volume
	pod.Spec.Volumes = append(pod.Spec.Volumes,
		corev1.Volume{
			Name: CAVolName,
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{},
			},
		},
	)

	// 2. Add Init Container
	image := InitContainerImage
	cmd := `echo "$CA_PEM" > /etc/kloak-ca/ca.crt`

	var envVars []corev1.EnvVar
	envVars = append(envVars, corev1.EnvVar{
		Name:  "CA_PEM",
		Value: caCert,
	})

	var volumeMounts []corev1.VolumeMount
	volumeMounts = append(volumeMounts, corev1.VolumeMount{
		Name:      CAVolName,
		MountPath: "/etc/kloak-ca",
	})

	initContainer := corev1.Container{
		Name:         "kloak-init",
		Image:        image,
		Command:      []string{"sh", "-c", cmd},
		Env:          envVars,
		VolumeMounts: volumeMounts,
	}
	pod.Spec.InitContainers = append(pod.Spec.InitContainers, initContainer)
}

// injectEnvoySidecar adds the Envoy sidecar container to the pod.
func (h *Handler) injectEnvoySidecar(pod *corev1.Pod) {
	const EnvoyConfigVolName = "kloak-envoy-config-vol"

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
				Name:      EnvoyConfigVolName,
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

	pod.Spec.Containers = append(pod.Spec.Containers, envoyContainer)
}

// mountCAVolume mounts the CA volume to all application containers.
func (h *Handler) mountCAVolume(pod *corev1.Pod) {
	const (
		CAVolName = "kloak-ca-vol"
		CAVolPath = "/etc/kloak-ca"
	)

	for i := range pod.Spec.Containers {
		pod.Spec.Containers[i].VolumeMounts = append(
			pod.Spec.Containers[i].VolumeMounts,
			corev1.VolumeMount{
				Name:      CAVolName,
				MountPath: CAVolPath,
				ReadOnly:  true,
			},
		)

		// Inject CA cert env vars for different runtimes
		fullPath := fmt.Sprintf("%s/%s", CAVolPath, CACertFile)
		pod.Spec.Containers[i].Env = append(
			pod.Spec.Containers[i].Env,
			corev1.EnvVar{
				Name:  "SSL_CERT_FILE",
				Value: fullPath,
			},
			corev1.EnvVar{
				Name:  "NODE_EXTRA_CA_CERTS",
				Value: fullPath,
			},
		)

		pod.Spec.Containers[i].Env = append(
			pod.Spec.Containers[i].Env,
			corev1.EnvVar{
				Name:  "JAVA_TOOL_OPTIONS",
				Value: fmt.Sprintf("-Djavax.net.ssl.trustStore=%s/%s -Djavax.net.ssl.trustStorePassword=%s -Djava.net.preferIPv4Stack=true", CAVolPath, JavaTruststoreFile, JavaTruststorePassword),
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
