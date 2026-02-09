#!/usr/bin/env bash
# Kloak Demo Setup Script (Lima + K3s)
# Creates a Lima VM with K3s and deploys the Kloak demo

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
CERT_DIR="/tmp/kloak-certs"
KUBECONFIG_PATH="/tmp/kloak-k3s.yaml"
CERT_DIR="/tmp/kloak-certs"
KUBECONFIG_PATH="/tmp/kloak-k3s.yaml"
LIMA_INSTANCE="kloak"
DEMO_NAMESPACE="kloak-demo"

echo "================================"
echo " Kloak Demo Setup (Lima + K3s)"
echo "================================"
echo ""
echo "PATH: $PATH"

# Check prerequisites
check_prereqs() {
    echo "Checking prerequisites..."
    for cmd in limactl kubectl docker openssl; do
        if ! command -v $cmd &> /dev/null; then
             echo "Debug: command -v $cmd failed"
             echo "Debug: which $cmd: $(which $cmd)"
            echo "Error: $cmd is required but not installed."
            exit 1
        fi
    done
    echo "✓ Prerequisites OK"
}

# Create/Start Lima VM with K3s
create_cluster() {
    echo ""
    echo "Starting Lima VM with K3s..."
    
    # Check if instance exists and has K3s
    if limactl list -q | grep -q "^${LIMA_INSTANCE}$"; then
        echo "Checking existing instance state..."
        # If K3s is missing, it's likely the old VM without port forwarding.
        if ! limactl shell "${LIMA_INSTANCE}" -- which k3s &>/dev/null; then
            echo "Existing instance lacks K3s configuration (or port forwarding). Recreating..."
            limactl delete -f "${LIMA_INSTANCE}"
        else
            echo "Instance '${LIMA_INSTANCE}' appears compatible."
        fi
    fi

    # Create/Start
    if ! limactl list -q | grep -q "^${LIMA_INSTANCE}$"; then
        echo "Creating Lima instance '${LIMA_INSTANCE}' from lima.yaml..."
        limactl start --name="${LIMA_INSTANCE}" "$ROOT_DIR/lima.yaml"
    else
        echo "Starting existing Lima instance '${LIMA_INSTANCE}'..."
        limactl start "${LIMA_INSTANCE}"
    fi

    # Ensure K3s is installed (in case provision script skipped or failed)
    echo "Ensuring K3s is installed..."
    limactl shell "${LIMA_INSTANCE}" -- sudo sh -c 'if [ ! -f /usr/local/bin/k3s ]; then curl -sfL https://get.k3s.io | sh -s - --write-kubeconfig-mode 644 --disable traefik; fi'

    # Wait for K3s service
    echo "Waiting for K3s service..."
    until limactl shell "${LIMA_INSTANCE}" -- sudo systemctl is-active k3s >/dev/null 2>&1; do
         sleep 5
         echo -n "."
    done

    # Wait for K3s kubeconfig
    echo "Waiting for K3s kubeconfig..."
    until limactl shell "${LIMA_INSTANCE}" -- sudo test -f /etc/rancher/k3s/k3s.yaml; do
        sleep 5
        echo -n "."
    done
    echo ""

    # Fetch and fix kubeconfig
    echo "Fetching kubeconfig..."
    limactl shell "${LIMA_INSTANCE}" -- sudo cat /etc/rancher/k3s/k3s.yaml > "$KUBECONFIG_PATH"
    # Ensure rights
    chmod 600 "$KUBECONFIG_PATH"
    # K3s uses 127.0.0.1:6443 which works via Lima port forwarding
    
    export KUBECONFIG="$KUBECONFIG_PATH"
    echo "✓ K3s ready. Kubeconfig: $KUBECONFIG_PATH"
    
    # Wait for node ready
    echo "Waiting for K3s node readiness..."
    kubectl wait --for=condition=Ready node --all --timeout=60s
}

# Build images and import to K3s
build_images() {
    echo ""
    echo "Building images..."
    
    # Build demo Python app
    docker build -t kloak-demo-python:latest "$SCRIPT_DIR/demo-python"
    
    # Build Kloak controller
    docker build -t kloak:latest "$ROOT_DIR"
    
    echo "Importing images into K3s (this may take a moment)..."
    # We pipeline docker save -> lima -> k3s ctr import
    
    echo "Importing kloak-demo-python..."
    docker save kloak-demo-python:latest | limactl shell "${LIMA_INSTANCE}" -- sudo k3s ctr images import -
    
    echo "Importing kloak..."
    docker save kloak:latest | limactl shell "${LIMA_INSTANCE}" -- sudo k3s ctr images import -
    
    echo "✓ Images built and imported"
}

# Generate TLS certificates (only if they don't exist)
generate_certs() {
    echo ""
    echo "Checking TLS certificates..."
    
    mkdir -p "$CERT_DIR"
    
    # Check if all required certs exist
    if [[ -f "$CERT_DIR/webhook-tls.crt" && -f "$CERT_DIR/webhook-tls.key" && \
          -f "$CERT_DIR/ca.crt" && -f "$CERT_DIR/ca.key" ]]; then
        echo "✓ TLS certificates already exist, skipping generation"
        return 0
    fi
    
    echo "Generating TLS certificates..."
    
    # Generate webhook TLS certificate (server cert, NOT CA)
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$CERT_DIR/webhook-tls.key" \
        -out "$CERT_DIR/webhook-tls.crt" \
        -days 365 -nodes \
        -subj "/CN=kloak-webhook.kloak-system.svc" \
        -addext "subjectAltName=DNS:kloak-webhook.kloak-system.svc,DNS:kloak-webhook.kloak-system.svc.cluster.local,DNS:kloak-webhook,DNS:localhost" \
        -addext "basicConstraints=critical,CA:FALSE" \
        -addext "keyUsage=digitalSignature,keyEncipherment" \
        -addext "extendedKeyUsage=serverAuth" \
        2>/dev/null
    
    # Generate Root CA for MITM
    openssl req -x509 -newkey rsa:4096 \
        -keyout "$CERT_DIR/ca.key" \
        -out "$CERT_DIR/ca.crt" \
        -days 3650 -nodes \
        -subj "/CN=Kloak Root CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash" \
        -addext "authorityKeyIdentifier=keyid:always,issuer" \
        2>/dev/null
    
    echo "✓ TLS certificates generated"
}

# Deploy Kloak components
deploy_kloak() {
    export KUBECONFIG="$KUBECONFIG_PATH"
    echo ""
    echo "Deploying Kloak..."
    
    # Apply RBAC first (creates namespace)
    kubectl apply -f "$ROOT_DIR/config/manifests/rbac.yaml"
    
    # Wait for namespace to be ready
    kubectl wait --for=jsonpath='{.status.phase}'=Active namespace/kloak-system --timeout=30s
    
    # Create webhook TLS secret
    kubectl create secret tls kloak-webhook-certs \
        --cert="$CERT_DIR/webhook-tls.crt" \
        --key="$CERT_DIR/webhook-tls.key" \
        -n kloak-system --dry-run=client -o yaml | kubectl apply -f -
    
    # Create CA secret for XDS
    kubectl create secret tls kloak-ca \
        --cert="$CERT_DIR/ca.crt" \
        --key="$CERT_DIR/ca.key" \
        -n kloak-system --dry-run=client -o yaml | kubectl apply -f -
    
    # Create Demo Namespace
    echo "Creating demo namespace: $DEMO_NAMESPACE"
    kubectl create namespace "$DEMO_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

    # Label demo namespace to enable webhook
    kubectl label namespace "$DEMO_NAMESPACE" getkloak.io/enabled=true --overwrite

    # Create CA ConfigMap for app pods (to trust our CA)
    kubectl create configmap kloak-ca-cert \
        --from-file=ca.crt="$CERT_DIR/ca.crt" \
        -n "$DEMO_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Create Envoy config
    kubectl create configmap kloak-envoy-config \
        --from-file="$ROOT_DIR/config/envoy/envoy.yaml" \
        -n "$DEMO_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Apply controller, agent, and webhook deployments
    kubectl apply -f "$ROOT_DIR/config/manifests/controller.yaml"
    kubectl apply -f "$ROOT_DIR/config/manifests/agent.yaml"
    kubectl apply -f "$ROOT_DIR/config/manifests/webhook.yaml"
    
    # Get the webhook CA bundle (same as the webhook cert for self-signed)
    CA_BUNDLE=$(base64 < "$CERT_DIR/webhook-tls.crt" | tr -d '\n')
    
    # Patch MutatingWebhookConfiguration with CA bundle
    kubectl patch mutatingwebhookconfiguration kloak-mutating-webhook \
        --type='json' -p="[{\"op\": \"replace\", \"path\": \"/webhooks/0/clientConfig/caBundle\", \"value\": \"${CA_BUNDLE}\"}]"
    
    # Remove default namespace label if it exists (cleanup)
    kubectl label namespace default getkloak.io/enabled- --overwrite 2>/dev/null || true
    
    echo "✓ Kloak components deployed (controller, agent, webhook)"
}

# Wait for Kloak pods
wait_for_kloak() {
    export KUBECONFIG="$KUBECONFIG_PATH"
    echo ""
    echo "Waiting for Kloak pods to be ready..."
    
    kubectl wait --for=condition=Ready pod \
        -l app.kubernetes.io/name=kloak \
        -n kloak-system \
        --timeout=120s || {
        echo "Warning: Some Kloak pods may not be ready"
        kubectl get pods -n kloak-system
    }
    
    echo ""
    echo "Kloak pods status:"
    kubectl get pods -n kloak-system
}

# Deploy demo app
deploy_demo() {
    export KUBECONFIG="$KUBECONFIG_PATH"
    echo ""
    echo "Deploying demo application to $DEMO_NAMESPACE..."
    
    # Delete any existing demo pod first
    kubectl delete pod demo-python -n "$DEMO_NAMESPACE" --ignore-not-found 2>/dev/null || true
    
    # Create SECRET 1: Allowed for httpbin.org
    echo "Creating secret-allowed (hosts=httpbin.org)..."
    kubectl create secret generic secret-allowed \
        --from-literal=api-key="REAL-ALLOWED-KEY-12345" \
        -n "$DEMO_NAMESPACE" --dry-run=client -o yaml | \
        kubectl label -f - getkloak.io/enabled="true" getkloak.io/hosts="httpbin.org" --local -o yaml | \
        kubectl apply -f -
    
    # Create SECRET 2: Blocked for httpbin.org (only allowed for example.com)
    echo "Creating secret-blocked (hosts=example.com)..."
    kubectl create secret generic secret-blocked \
        --from-literal=api-key="REAL-BLOCKED-KEY-67890" \
        -n "$DEMO_NAMESPACE" --dry-run=client -o yaml | \
        kubectl label -f - getkloak.io/enabled="true" getkloak.io/hosts="example.com" --local -o yaml | \
        kubectl apply -f -
    
    # Wait a moment for cleanup
    sleep 2
    
    # Apply the demo pod (webhook should inject sidecar)
    kubectl apply -f "$SCRIPT_DIR/demo-python/pod.yaml" -n "$DEMO_NAMESPACE"
    
    echo "✓ Demo application deployed"
}

# Wait for demo pod
wait_for_demo() {
    export KUBECONFIG="$KUBECONFIG_PATH"
    echo ""
    echo "Waiting for demo pod to be ready..."
    
    kubectl wait --for=condition=Ready pod/demo-python -n "$DEMO_NAMESPACE" --timeout=120s || {
        echo "Warning: Demo pod may not be ready"
    }
    
    echo ""
    echo "Demo pod status:"
    kubectl get pod demo-python -n "$DEMO_NAMESPACE" -o wide
    
    echo ""
    echo "Containers in demo pod:"
    kubectl get pod demo-python -n "$DEMO_NAMESPACE" -o jsonpath='{.spec.containers[*].name}' && echo ""
}

# Verify sidecar injection
verify_injection() {
    export KUBECONFIG="$KUBECONFIG_PATH"
    echo ""
    echo "Verifying sidecar injection..."
    
    CONTAINERS=$(kubectl get pod demo-python -n "$DEMO_NAMESPACE" -o jsonpath='{.spec.containers[*].name}' 2>/dev/null || echo "")
    
    if echo "$CONTAINERS" | grep -q "envoy-sidecar"; then
        echo "✓ Envoy sidecar successfully injected!"
        echo "  Containers: $CONTAINERS"
    else
        echo "✗ Envoy sidecar NOT found"
        echo "  Containers: $CONTAINERS"
        echo ""
        echo "Checking webhook logs..."
        kubectl logs -n kloak-system -l app.kubernetes.io/component=webhook --tail=10 2>/dev/null || true
    fi
}

# Show summary
show_summary() {
    echo ""
    echo "================================"
    echo " Demo Setup Complete!"
    echo "================================"
    echo ""
    echo "Environment:"
    echo "  Kubeconfig:          $KUBECONFIG_PATH"
    echo "  Metrics:             http://localhost:8080 (forwarded)"
    echo ""
    echo "Commands:"
    echo "  Use kubectl:         export KUBECONFIG=$KUBECONFIG_PATH"
    echo "  View demo logs:      kubectl logs -f demo-python -n $DEMO_NAMESPACE -c demo-app"
    echo "  View sidecar logs:   kubectl logs -f demo-python -n $DEMO_NAMESPACE -c envoy-sidecar"
    echo "  View webhook logs:   kubectl logs -n kloak-system -l app.kubernetes.io/component=webhook"
    echo ""
    echo "Verification:"
    echo "  1. Check demo logs:  kubectl logs demo-python -n $DEMO_NAMESPACE -c demo-app | head -30"
    echo "     (Should show 'kloak:...' UUIDs for both secrets)"
    echo "  2. Check response:   kubectl logs demo-python -n $DEMO_NAMESPACE -c demo-app | grep -A20 'Response headers'"
    echo "     X-Secret-Allowed: Should show 'REAL-ALLOWED-KEY-12345' (replaced)"
    echo "     X-Secret-Blocked: Should show 'kloak:...' UUID (NOT replaced - wrong host)"
    echo ""
}

# Main
main() {
    check_prereqs
    create_cluster
    build_images
    generate_certs
    deploy_kloak
    wait_for_kloak
    deploy_demo
    wait_for_demo
    verify_injection
    show_summary
}

main "$@"
