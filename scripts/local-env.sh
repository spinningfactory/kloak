#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

lima_exec() {
    limactl shell kloak -- bash -lc "export KUBECONFIG=/etc/rancher/k3s/k3s.yaml; $1"
}

echo "==> Ensuring Lima VM is running..."
make -C "$REPO_ROOT" lima-ensure

echo "==> Building kloak controller image..."
lima_exec "cd $REPO_ROOT && docker build -t kloak:latest ."

echo "==> Building demo images..."
lima_exec "cd $REPO_ROOT && docker build -t kloak-demo-go:latest ./examples/demo-go/"
lima_exec "cd $REPO_ROOT && docker build -t kloak-demo-python:latest ./examples/demo-python/"
lima_exec "cd $REPO_ROOT && docker build -t kloak-demo-rust-openssl:latest ./examples/demo-rust-openssl/"

echo "==> Importing images into k3s..."
lima_exec "docker save kloak:latest | sudo k3s ctr images import -"
lima_exec "docker save kloak-demo-go:latest | sudo k3s ctr images import -"
lima_exec "docker save kloak-demo-python:latest | sudo k3s ctr images import -"
lima_exec "docker save kloak-demo-rust-openssl:latest | sudo k3s ctr images import -"

echo "==> Creating kloak-system namespace..."
lima_exec "kubectl create ns kloak-system --dry-run=client -o yaml | kubectl apply -f -"

echo "==> Deploying ClickHouse..."
lima_exec "kubectl apply -f $REPO_ROOT/test/e2e/clickhouse.yaml -n kloak-system"

echo "==> Waiting for ClickHouse to be ready..."
until lima_exec "kubectl get deploy/clickhouse -n kloak-system -o jsonpath='{.status.availableReplicas}'" 2>/dev/null | grep -q '^[1-9]'; do
    echo "    ...waiting for ClickHouse..."
    sleep 5
done
echo "    ClickHouse ready."

echo "==> Deploying OTel Collector..."
lima_exec "kubectl apply -f $REPO_ROOT/test/e2e/otel-collector.yaml -n kloak-system"

echo "==> Waiting for OTel Collector to be ready..."
lima_exec "kubectl rollout status deployment/otel-collector -n kloak-system --timeout=120s"

echo "==> Installing kloak via Helm..."
lima_exec "helm upgrade --install kloak $REPO_ROOT/charts/kloak -n kloak-system -f $REPO_ROOT/deploy/local-env/values-local.yaml --wait --timeout 120s"

echo "==> Waiting for kloak controller DaemonSet to be ready..."
lima_exec "kubectl rollout status daemonset/kloak-controller -n kloak-system --timeout=120s"

echo "==> Creating kloak-local namespace..."
lima_exec "kubectl create ns kloak-local --dry-run=client -o yaml | kubectl apply -f - && kubectl label ns kloak-local getkloak.io/enabled=true --overwrite"

echo "==> Applying secrets and demo apps..."
lima_exec "kubectl apply -f $REPO_ROOT/deploy/local-env/secrets.yaml -n kloak-local && kubectl apply -f $REPO_ROOT/deploy/local-env/apps.yaml -n kloak-local"

echo "==> Waiting for demo deployments to be ready..."
lima_exec "kubectl rollout status deployment/demo-go -n kloak-local --timeout=120s"
lima_exec "kubectl rollout status deployment/demo-python -n kloak-local --timeout=120s"
lima_exec "kubectl rollout status deployment/demo-rust-openssl -n kloak-local --timeout=120s"

echo ""
echo "==> Local environment ready!"
echo ""
lima_exec "kubectl get pods -n kloak-system && echo '' && kubectl get pods -n kloak-local"
