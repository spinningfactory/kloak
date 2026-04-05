#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Parse args
SCALE=5
INTERVAL=1
while [[ $# -gt 0 ]]; do
    case $1 in
        --scale) SCALE="$2"; shift 2 ;;
        --interval) INTERVAL="$2"; shift 2 ;;
        *) echo "Usage: $0 [--scale N] [--interval S]"; exit 1 ;;
    esac
done

lima_exec() {
    limactl shell kloak -- bash -lc "export KUBECONFIG=/etc/rancher/k3s/k3s.yaml; $1"
}

echo "==> Scaling demo deployments to $SCALE replicas with REQUEST_INTERVAL=${INTERVAL}s..."

lima_exec "kubectl scale deployment/demo-go deployment/demo-python deployment/demo-rust-openssl --replicas=$SCALE -n kloak-local"

echo "==> Patching REQUEST_INTERVAL on each deployment..."
lima_exec "kubectl set env deployment/demo-go REQUEST_INTERVAL=$INTERVAL -n kloak-local"
lima_exec "kubectl set env deployment/demo-python REQUEST_INTERVAL=$INTERVAL -n kloak-local"
lima_exec "kubectl set env deployment/demo-rust-openssl REQUEST_INTERVAL=$INTERVAL -n kloak-local"

echo "==> Waiting for rollouts..."
lima_exec "kubectl rollout status deployment/demo-go -n kloak-local --timeout=60s"
lima_exec "kubectl rollout status deployment/demo-python -n kloak-local --timeout=60s"
lima_exec "kubectl rollout status deployment/demo-rust-openssl -n kloak-local --timeout=60s"

echo "==> Waiting 30s for metrics to accumulate..."
sleep 30

echo "==> Querying ClickHouse for report..."
echo ""

echo "--- Latest rewrite counts by pod/secret ---"
lima_exec "kubectl exec -n kloak-system deploy/clickhouse -- clickhouse-client --query \"SELECT Attributes['pod_name'] as pod, Attributes['secret_name'] as secret, argMax(Value, TimeUnix) as rewrites FROM otel.otel_metrics_sum WHERE MetricName='kloak_tls_rewrite_total' AND Attributes['pod_name']!='' GROUP BY pod, secret ORDER BY rewrites DESC\""

echo ""
echo "--- Top eBPF debug counters ---"
lima_exec "kubectl exec -n kloak-system deploy/clickhouse -- clickhouse-client --query \"SELECT Attributes['counter'] as counter, max(Value) as value FROM otel.otel_metrics_gauge WHERE MetricName='kloak_ebpf_debug_counter' GROUP BY counter HAVING value > 0 ORDER BY value DESC LIMIT 10\""

echo ""
echo "--- BPF map sizes ---"
lima_exec "kubectl exec -n kloak-system deploy/clickhouse -- clickhouse-client --query \"SELECT Attributes['map'] as map, argMax(Value, TimeUnix) as entries FROM otel.otel_metrics_gauge WHERE MetricName='kloak_bpf_map_entries' GROUP BY map\""

echo ""
echo "==> Load test report complete."
