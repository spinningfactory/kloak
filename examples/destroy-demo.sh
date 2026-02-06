#!/bin/bash
# Kloak Demo Destroy Script
# Completely removes the Kind cluster and cleans up resources

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="/tmp/kloak-certs"

echo "================================"
echo " Kloak Demo Cleanup"
echo "================================"
echo ""

# Delete Kind cluster
delete_cluster() {
    echo "Deleting Kind cluster..."
    
    if kind get clusters 2>/dev/null | grep -q "kloak-demo"; then
        kind delete cluster --name kloak-demo
        echo "✓ Kind cluster deleted"
    else
        echo "✓ Kind cluster not found (already deleted)"
    fi
}

# Clean up certificates
cleanup_certs() {
    echo ""
    echo "Cleaning up certificates..."
    
    if [ -d "$CERT_DIR" ]; then
        rm -rf "$CERT_DIR"
        echo "✓ Certificates cleaned up"
    else
        echo "✓ No certificates to clean"
    fi
}

# Clean up Docker images (optional)
cleanup_images() {
    echo ""
    read -p "Remove Docker images? [y/N] " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker rmi kloak:latest 2>/dev/null || true
        docker rmi kloak-demo-python:latest 2>/dev/null || true
        echo "✓ Docker images removed"
    else
        echo "✓ Docker images kept"
    fi
}

# Main
main() {
    delete_cluster
    cleanup_certs
    cleanup_images
    
    echo ""
    echo "================================"
    echo " Cleanup Complete!"
    echo "================================"
    echo ""
    echo "To redeploy: $SCRIPT_DIR/setup-demo.sh"
    echo ""
}

main "$@"
