#!/usr/bin/env bash
# Quick redeploy: rebuild kloak image and restart controller only.
# Usage: make generate-ebpf && ./examples/redeploy.sh
#
# Skips: Lima VM setup, K3s install, demo image builds, demo redeployment.
# Only rebuilds the kloak controller image and restarts it.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
KUBECONFIG_PATH="/tmp/kloak-k3s.yaml"
LIMA_INSTANCE="kloak"

export KUBECONFIG="$KUBECONFIG_PATH"

echo "==> Building kloak image..."
docker build -t kloak:latest "$ROOT_DIR"

echo "==> Importing into K3s..."
docker save kloak:latest | limactl shell "${LIMA_INSTANCE}" -- sudo k3s ctr images import -

echo "==> Restarting controller..."
kubectl rollout restart daemonset/kloak-controller -n kloak-system

echo "==> Waiting for rollout..."
kubectl rollout status daemonset/kloak-controller -n kloak-system --timeout=60s

echo "==> Controller logs:"
sleep 3
kubectl logs -n kloak-system -l app.kubernetes.io/component=controller --tail=20

echo ""
echo "Done. Monitor with:"
echo "  kubectl logs -f -n kloak-system -l app.kubernetes.io/component=controller"
