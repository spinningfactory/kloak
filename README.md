# Kloak

Kubernetes eBPF HTTPS Interceptor with Envoy Sidecar Injection.

## Overview

Kloak transparently intercepts HTTPS traffic from labeled Kubernetes pods, bypasses SSL verification via eBPF, and routes through an Envoy sidecar that can rewrite headers using a hash-to-value conversion table.

## Quick Start

```bash
# Build
make build

# Run tests
make test

# Build Docker image
make docker-build
```

## Project Status

🚧 **Under Development** - See implementation plan for progress.

## License

Apache 2.0
