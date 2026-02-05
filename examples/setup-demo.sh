#!/bin/bash
# Bouncer Demo Setup Script
# Creates a Kind cluster and deploys the Bouncer demo

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
CERT_DIR="/tmp/bouncer-certs"

echo "================================"
echo " Bouncer Demo Setup"
echo "================================"
echo ""

# Check prerequisites
check_prereqs() {
    echo "Checking prerequisites..."
    for cmd in kind kubectl docker openssl; do
        if ! command -v $cmd &> /dev/null; then
            echo "Error: $cmd is required but not installed."
            exit 1
        fi
    done
    echo "✓ Prerequisites OK"
}

# Create Kind cluster
create_cluster() {
    echo ""
    echo "Creating Kind cluster..."
    
    # Delete existing cluster if any
    kind delete cluster --name bouncer-demo 2>/dev/null || true
    
    # Create cluster
    kind create cluster --config "$SCRIPT_DIR/kind-cluster.yaml"
    
    echo "✓ Kind cluster created"
}

# Build images
build_images() {
    echo ""
    echo "Building images..."
    
    # Build demo Python app
    docker build -t bouncer-demo-python:latest "$SCRIPT_DIR/demo-python"
    
    # Build Bouncer controller
    docker build -t bouncer:latest "$ROOT_DIR"
    
    # Load images into Kind
    kind load docker-image bouncer-demo-python:latest --name bouncer-demo
    kind load docker-image bouncer:latest --name bouncer-demo
    
    echo "✓ Images built and loaded"
}

# Generate TLS certificates
generate_certs() {
    echo ""
    echo "Generating TLS certificates..."
    
    rm -rf "$CERT_DIR"
    mkdir -p "$CERT_DIR"
    
    # Generate webhook TLS certificate
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$CERT_DIR/webhook-tls.key" \
        -out "$CERT_DIR/webhook-tls.crt" \
        -days 365 -nodes \
        -subj "/CN=bouncer-webhook.bouncer-system.svc" \
        -addext "subjectAltName=DNS:bouncer-webhook.bouncer-system.svc,DNS:bouncer-webhook.bouncer-system.svc.cluster.local,DNS:bouncer-webhook,DNS:localhost" \
        2>/dev/null
    
    # Generate Root CA for MITM
    openssl req -x509 -newkey rsa:4096 \
        -keyout "$CERT_DIR/ca.key" \
        -out "$CERT_DIR/ca.crt" \
        -days 3650 -nodes \
        -subj "/CN=Bouncer Root CA" \
        2>/dev/null
    
    echo "✓ TLS certificates generated"
}

# Deploy Bouncer components
deploy_bouncer() {
    echo ""
    echo "Deploying Bouncer..."
    
    # Apply RBAC first (creates namespace)
    kubectl apply -f "$ROOT_DIR/config/manifests/rbac.yaml"
    
    # Wait for namespace to be ready
    kubectl wait --for=jsonpath='{.status.phase}'=Active namespace/bouncer-system --timeout=30s
    
    # Create webhook TLS secret
    kubectl create secret tls bouncer-webhook-certs \
        --cert="$CERT_DIR/webhook-tls.crt" \
        --key="$CERT_DIR/webhook-tls.key" \
        -n bouncer-system --dry-run=client -o yaml | kubectl apply -f -
    
    # Create CA secret for XDS
    kubectl create secret tls bouncer-ca \
        --cert="$CERT_DIR/ca.crt" \
        --key="$CERT_DIR/ca.key" \
        -n bouncer-system --dry-run=client -o yaml | kubectl apply -f -
    
    # Create CA ConfigMap for app pods (to trust our CA)
    kubectl create configmap bouncer-ca-cert \
        --from-file=ca.crt="$CERT_DIR/ca.crt" \
        -n default --dry-run=client -o yaml | kubectl apply -f -
    
    # Create Envoy config
    kubectl create configmap bouncer-envoy-config \
        --from-file="$ROOT_DIR/config/envoy/envoy.yaml" \
        -n default --dry-run=client -o yaml | kubectl apply -f -
    
    # Apply controller, webhook, and xds deployments
    kubectl apply -f "$ROOT_DIR/config/manifests/controller.yaml"
    kubectl apply -f "$ROOT_DIR/config/manifests/webhook.yaml"
    kubectl apply -f "$ROOT_DIR/config/manifests/xds.yaml"
    
    # Get the webhook CA bundle (same as the webhook cert for self-signed)
    CA_BUNDLE=$(base64 < "$CERT_DIR/webhook-tls.crt" | tr -d '\n')
    
    # Patch MutatingWebhookConfiguration with CA bundle
    kubectl patch mutatingwebhookconfiguration bouncer-mutating-webhook \
        --type='json' -p="[{\"op\": \"replace\", \"path\": \"/webhooks/0/clientConfig/caBundle\", \"value\": \"${CA_BUNDLE}\"}]"
    
    # Label default namespace to enable webhook
    kubectl label namespace default bouncer.io/enabled=true --overwrite
    
    echo "✓ Bouncer components deployed"
}

# Wait for Bouncer pods
wait_for_bouncer() {
    echo ""
    echo "Waiting for Bouncer pods to be ready..."
    
    kubectl wait --for=condition=Ready pod \
        -l app.kubernetes.io/name=bouncer \
        -n bouncer-system \
        --timeout=120s || {
        echo "Warning: Some Bouncer pods may not be ready"
        kubectl get pods -n bouncer-system
    }
    
    echo ""
    echo "Bouncer pods status:"
    kubectl get pods -n bouncer-system
}

# Deploy demo app
deploy_demo() {
    echo ""
    echo "Deploying demo application..."
    
    # Delete any existing demo pod first
    kubectl delete pod demo-python --ignore-not-found 2>/dev/null || true
    
    # Wait a moment for cleanup
    sleep 2
    
    # Apply the demo pod (webhook should inject sidecar)
    kubectl apply -f "$SCRIPT_DIR/demo-python/pod.yaml"
    
    echo "✓ Demo application deployed"
}

# Wait for demo pod
wait_for_demo() {
    echo ""
    echo "Waiting for demo pod to be ready..."
    
    kubectl wait --for=condition=Ready pod/demo-python --timeout=120s || {
        echo "Warning: Demo pod may not be ready"
    }
    
    echo ""
    echo "Demo pod status:"
    kubectl get pod demo-python -o wide
    
    echo ""
    echo "Containers in demo pod:"
    kubectl get pod demo-python -o jsonpath='{.spec.containers[*].name}' && echo ""
}

# Verify sidecar injection
verify_injection() {
    echo ""
    echo "Verifying sidecar injection..."
    
    CONTAINERS=$(kubectl get pod demo-python -o jsonpath='{.spec.containers[*].name}' 2>/dev/null || echo "")
    
    if echo "$CONTAINERS" | grep -q "envoy-sidecar"; then
        echo "✓ Envoy sidecar successfully injected!"
        echo "  Containers: $CONTAINERS"
    else
        echo "✗ Envoy sidecar NOT found"
        echo "  Containers: $CONTAINERS"
        echo ""
        echo "Checking webhook logs..."
        kubectl logs -n bouncer-system -l app.kubernetes.io/component=webhook --tail=10 2>/dev/null || true
    fi
}

# Show summary
show_summary() {
    echo ""
    echo "================================"
    echo " Demo Setup Complete!"
    echo "================================"
    echo ""
    echo "Commands:"
    echo "  View demo logs:      kubectl logs -f demo-python -c demo-app"
    echo "  View sidecar logs:   kubectl logs -f demo-python -c envoy-sidecar"
    echo "  View webhook logs:   kubectl logs -n bouncer-system -l app.kubernetes.io/component=webhook"
    echo "  View controller logs: kubectl logs -n bouncer-system -l app.kubernetes.io/component=controller"
    echo "  Destroy demo:        $SCRIPT_DIR/destroy-demo.sh"
    echo ""
}

# Main
main() {
    check_prereqs
    create_cluster
    build_images
    generate_certs
    deploy_bouncer
    wait_for_bouncer
    deploy_demo
    wait_for_demo
    verify_injection
    show_summary
}

main "$@"
