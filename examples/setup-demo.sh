#!/bin/bash
# Bouncer Demo Setup Script
# Creates a Kind cluster and deploys the Bouncer demo

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "================================"
echo " Bouncer Demo Setup"
echo "================================"
echo ""

# Check prerequisites
check_prereqs() {
    for cmd in kind kubectl docker; do
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
    
    # Build Bouncer controller (if exists)
    if [ -f "$ROOT_DIR/Dockerfile" ]; then
        docker build -t bouncer:latest "$ROOT_DIR"
    fi
    
    # Load images into Kind
    kind load docker-image bouncer-demo-python:latest --name bouncer-demo
    
    echo "✓ Images built and loaded"
}

# Deploy Bouncer components
deploy_bouncer() {
    echo ""
    echo "Deploying Bouncer..."
    
    # Build Bouncer controller
    echo "Building Bouncer controller image..."
    docker build -t bouncer:latest "$ROOT_DIR"
    kind load docker-image bouncer:latest --name bouncer-demo
    
    # Apply RBAC first
    kubectl apply -f "$ROOT_DIR/config/manifests/rbac.yaml"
    
    # Create webhook TLS certs (self-signed for demo)
    echo "Generating webhook certificates..."
    mkdir -p /tmp/bouncer-certs
    openssl req -x509 -newkey rsa:2048 -keyout /tmp/bouncer-certs/tls.key \
        -out /tmp/bouncer-certs/tls.crt -days 365 -nodes \
        -subj "/CN=bouncer-webhook.bouncer-system.svc" 2>/dev/null
    
    kubectl create secret tls bouncer-webhook-certs \
        --cert=/tmp/bouncer-certs/tls.crt \
        --key=/tmp/bouncer-certs/tls.key \
        -n bouncer-system --dry-run=client -o yaml | kubectl apply -f -
    
    # Create CA secret (self-signed for demo)
    openssl req -x509 -newkey rsa:4096 -keyout /tmp/bouncer-certs/ca.key \
        -out /tmp/bouncer-certs/ca.crt -days 3650 -nodes \
        -subj "/CN=Bouncer Root CA" 2>/dev/null
    
    kubectl create secret tls bouncer-ca \
        --cert=/tmp/bouncer-certs/ca.crt \
        --key=/tmp/bouncer-certs/ca.key \
        -n bouncer-system --dry-run=client -o yaml | kubectl apply -f -
    
    # Create CA ConfigMap for app pods
    kubectl create configmap bouncer-ca-cert \
        --from-file=ca.crt=/tmp/bouncer-certs/ca.crt \
        -n default --dry-run=client -o yaml | kubectl apply -f -
    
    # Create Envoy config
    kubectl create configmap bouncer-envoy-config \
        --from-file="$ROOT_DIR/config/envoy/envoy.yaml" \
        -n default --dry-run=client -o yaml | kubectl apply -f -
    
    # Patch webhook config with CA bundle
    CA_BUNDLE=$(cat /tmp/bouncer-certs/tls.crt | base64 | tr -d '\n')
    
    # Apply controller, webhook, and xds
    kubectl apply -f "$ROOT_DIR/config/manifests/controller.yaml"
    kubectl apply -f "$ROOT_DIR/config/manifests/webhook.yaml"
    kubectl apply -f "$ROOT_DIR/config/manifests/xds.yaml"
    
    # Patch the webhook with CA bundle
    kubectl patch mutatingwebhookconfiguration bouncer-mutating-webhook \
        --type='json' -p="[{\"op\": \"replace\", \"path\": \"/webhooks/0/clientConfig/caBundle\", \"value\": \"${CA_BUNDLE}\"}]"
    
    # Label default namespace for webhook
    kubectl label namespace default bouncer.io/enabled=true --overwrite
    
    echo "✓ Bouncer components deployed"
}

# Deploy demo app
deploy_demo() {
    echo ""
    echo "Deploying demo application..."
    
    kubectl apply -f "$SCRIPT_DIR/demo-python/pod.yaml"
    
    echo "✓ Demo application deployed"
}

# Wait for pods
wait_for_pods() {
    echo ""
    echo "Waiting for pods to be ready..."
    
    kubectl wait --for=condition=Ready pod/demo-python --timeout=60s || true
    
    echo ""
    echo "Pod status:"
    kubectl get pods
}

# Show logs
show_logs() {
    echo ""
    echo "================================"
    echo " Demo Logs (Ctrl+C to exit)"
    echo "================================"
    echo ""
    
    kubectl logs -f demo-python -c demo-app 2>/dev/null || \
        echo "Logs not available yet, waiting..."
}

# Main
main() {
    check_prereqs
    create_cluster
    build_images
    deploy_bouncer
    deploy_demo
    wait_for_pods
    
    echo ""
    echo "================================"
    echo " Demo Setup Complete!"
    echo "================================"
    echo ""
    echo "To view logs:  kubectl logs -f demo-python"
    echo "To clean up:   kind delete cluster --name bouncer-demo"
    echo ""
    
    read -p "Show demo logs now? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        show_logs
    fi
}

main "$@"
