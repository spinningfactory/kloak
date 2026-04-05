#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

lima_exec() {
    limactl shell kloak -- bash -lc "export KUBECONFIG=/etc/rancher/k3s/k3s.yaml; $1"
}

echo "==> Uninstalling kloak Helm release..."
lima_exec "helm uninstall kloak -n kloak-system" || true

echo "==> Deleting kloak-local namespace..."
lima_exec "kubectl delete ns kloak-local --ignore-not-found"

echo "==> Removing OTel Collector..."
lima_exec "kubectl delete -f $REPO_ROOT/test/e2e/otel-collector.yaml -n kloak-system" || true

echo "==> Removing ClickHouse..."
lima_exec "kubectl delete -f $REPO_ROOT/test/e2e/clickhouse.yaml -n kloak-system" || true

echo "==> Local environment torn down."
