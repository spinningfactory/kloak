# Kloak

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go)](https://go.dev/)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.28+-326CE5?logo=kubernetes)](https://kubernetes.io/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**Kubernetes eBPF HTTPS Interceptor with Envoy Sidecar Injection**

Kloak transparently intercepts HTTPS traffic from labeled Kubernetes pods, enabling secure API key management without exposing secrets in plain text. It uses a hash-to-value conversion system to replace secret placeholders with actual values at runtime.

## Features

- 🔐 **Secure Secret Management** - Replace hashed placeholders with real secrets at the edge
- 🚀 **Transparent HTTPS Interception** - eBPF-powered traffic redirection
- 🎯 **Host-Based Restrictions** - Control which secrets can be used with which hosts
- ⚡ **Envoy Sidecar Injection** - Automatic sidecar injection via mutating webhook
- 🔧 **xDS Integration** - Dynamic configuration via SDS (Secret Discovery Service) and LDS (Listener Discovery Service)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Kubernetes Cluster                       │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐     ┌──────────────────────────────────┐  │
│  │  kloak-controller│────▶│         xDS Server               │  │
│  │  (watches secrets)│     │  (SDS + LDS + ExtProc)           │  │
│  └──────────────────┘     └──────────────────────────────────┘  │
│           │                              │                       │
│           │                              │                       │
│           ▼                              ▼                       │
│  ┌──────────────────┐     ┌──────────────────────────────────┐  │
│  │   kloak-webhook  │     │         Application Pod          │  │
│  │  (mutating       │     │  ┌─────────┐    ┌─────────────┐  │  │
│  │   admission)     │────▶│  │   App   │───▶│   Envoy     │  │  │
│  └──────────────────┘     │  │Container│    │  Sidecar    │  │  │
│                           │  └─────────┘    └─────────────┘  │  │
│                           └──────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Components

| Component | Description |
|-----------|-------------|
| **Controller** | Watches Kubernetes secrets with `getkloak.io/enabled=true` label and manages the hash-to-value mapping |
| **Webhook** | Mutating admission webhook that injects Envoy sidecars into labeled pods |
| **xDS Server** | Provides SDS for dynamic certificates and ExtProc for header transformation |
| **eBPF** | Redirects HTTPS traffic to the local Envoy sidecar (Linux only) |

## Quick Start

### Prerequisites

- **macOS**: Docker, Lima, kubectl, openssl
- **Linux**: Docker, kubectl, openssl

### Demo Setup

The easiest way to try Kloak is to run the demo:

```bash
# Run the full demo (creates Lima VM with K3s, deploys everything)
./examples/setup-demo.sh

# Access the cluster
export KUBECONFIG=/tmp/kloak-k3s.yaml

# View demo logs
kubectl logs -f demo-python -n kloak-demo -c demo-app

# Cleanup
./examples/destroy-demo.sh
```

### Manual Build

```bash
# Build binary
make build

# Run tests
make test

# Build Docker image
make docker-build
```

### eBPF Development (macOS)

Kloak uses Lima for eBPF development on macOS:

```bash
# Start Lima VM
make lima-start

# Generate eBPF code
make generate-ebpf

# Run tests in Linux VM
make test-linux

# Shell into VM
make lima-shell
```

## Configuration

### Labeling Secrets

To enable a secret for Kloak transformation:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-api-key
  labels:
    getkloak.io/enabled: "true"
    getkloak.io/hosts: "api.example.com"  # Optional: restrict to specific hosts
data:
  api-key: <base64-encoded-value>
```

### Labeling Namespaces

Enable sidecar injection for a namespace:

```bash
kubectl label namespace my-namespace getkloak.io/enabled=true
```

## Project Structure

```
kloak/
├── cmd/kloak/           # CLI commands (controller, webhook)
├── pkg/
│   ├── ca/              # Certificate authority management
│   ├── controller/      # Kubernetes controller logic
│   ├── ebpf/            # eBPF programs and Go bindings
│   ├── extproc/         # Envoy external processor
│   ├── hash/            # Hash-to-value mapping
│   ├── lds/             # Listener Discovery Service
│   ├── sds/             # Secret Discovery Service
│   ├── storage/         # Secret storage backend
│   ├── webhook/         # Admission webhook
│   └── xds/             # xDS server implementation
├── bpf/                 # eBPF C source code
├── config/
│   ├── envoy/           # Envoy configuration templates
│   └── manifests/       # Kubernetes manifests
└── examples/            # Demo applications
```

## Make Targets

| Target | Description |
|--------|-------------|
| `make build` | Build the kloak binary |
| `make build-linux` | Build for Linux (uses Lima on macOS) |
| `make test` | Run tests |
| `make test-linux` | Run tests in Linux VM |
| `make docker-build` | Build Docker image |
| `make generate-ebpf` | Generate eBPF Go bindings |
| `make generate-vmlinux` | Generate vmlinux.h from kernel BTF |
| `make lima-start` | Start the Lima VM |
| `make lima-stop` | Stop the Lima VM |
| `make lima-shell` | Open shell in Lima VM |
| `make help` | Show all available targets |

## How It Works

1. **Secret Registration**: The controller watches secrets labeled with `getkloak.io/enabled=true` and generates a unique hash (UUID) for each secret value.

2. **Sidecar Injection**: When a pod is created in a labeled namespace, the webhook injects an Envoy sidecar configured to intercept HTTPS traffic.

3. **Traffic Interception**: The eBPF program redirects outbound HTTPS traffic to the local Envoy sidecar.

4. **Header Transformation**: Envoy's external processor replaces hash placeholders (`kloak:UUID`) in headers with actual secret values, respecting host restrictions.

5. **Secure Transmission**: The request continues to its destination with real credentials, without the application ever seeing the actual secret.

## License

Apache 2.0
