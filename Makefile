.PHONY: all build build-linux test test-linux e2e e2e-setup e2e-run e2e-cleanup \
        e2e-ebpf e2e-ebpf-setup e2e-ebpf-run e2e-ebpf-cleanup \
        clean deps docker-build generate-ebpf generate-vmlinux run help \
        lima-start lima-stop lima-delete lima-shell lima-exec lima-check

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod
GOGENERATE=$(GOCMD) generate

# Binary names
BINARY_NAME=kloak
WEBHOOK_BINARY=kloak-webhook

# Proto generation
.PHONY: proto
proto:
	buf generate


# Build directories
BUILD_DIR=bin
CMD_DIR=cmd
BPF_DIR=pkg/ebpf
EBPF_PKG=pkg/ebpf

# Source files
GO_SOURCES=$(shell find . -name '*.go' -not -path './vendor/*')
BPF_SOURCES=$(wildcard $(BPF_DIR)/*.c $(BPF_DIR)/*.h)
EBPF_GENERATED=$(EBPF_PKG)/tlsuprobe_bpfel.go $(EBPF_PKG)/tlsuprobe_bpfeb.go

# Docker
DOCKER_IMAGE=kloak
DOCKER_TAG=latest

# Lima VM
LIMA_VM=kloak
LIMA_WORKDIR=$(shell pwd)
LIMA_CONFIG=lima.yaml

# ============================================================================
# Main targets
# ============================================================================

all: build

# Build depends on Go sources (and generated eBPF on Linux)
build: deps $(BUILD_DIR)/$(BINARY_NAME)

$(BUILD_DIR)/$(BINARY_NAME): $(GO_SOURCES)
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)/kloak

# Build for Linux (cross-compile or via Lima)
build-linux: lima-ensure
	@if [ "$$(uname)" = "Linux" ]; then \
		GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-linux ./$(CMD_DIR)/kloak; \
	else \
		$(MAKE) lima-exec CMD="cd $(LIMA_WORKDIR) && go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux ./$(CMD_DIR)/kloak"; \
	fi

test: deps
	$(GOTEST) -v ./...

# Run tests in Linux VM (for eBPF tests) - depends on Lima running
test-linux: lima-ensure
	$(MAKE) lima-exec CMD="cd $(LIMA_WORKDIR) && go test -v ./..."

# E2E cluster and image configuration
E2E_CLUSTER=kloak-e2e
E2E_IMAGE_TAG=e2e

# Full e2e: setup cluster, run tests, tear down.
e2e: e2e-setup e2e-run e2e-cleanup

# Create k3d cluster, build and import images.
e2e-setup:
	@which k3d > /dev/null || (echo "Error: k3d not found. Install with: brew install k3d" && exit 1)
	@echo "==> Creating k3d cluster '$(E2E_CLUSTER)'..."
	@k3d cluster create $(E2E_CLUSTER) --wait --timeout 120s 2>/dev/null || true
	@echo "==> Building kloak image..."
	@docker build -t $(DOCKER_IMAGE):$(E2E_IMAGE_TAG) .
	@echo "==> Importing images into k3d..."
	@k3d image import $(DOCKER_IMAGE):$(E2E_IMAGE_TAG) -c $(E2E_CLUSTER)
	@docker pull bitnami/kubectl:latest
	@k3d image import bitnami/kubectl:latest -c $(E2E_CLUSTER)
	@echo "==> E2E environment ready."

# Run e2e tests against an existing k3d cluster (use after e2e-setup).
e2e-run:
	KUBECONFIG=$$(k3d kubeconfig write $(E2E_CLUSTER)) $(GOTEST) -v -timeout 300s -count=1 ./test/e2e/

# Tear down e2e k3d cluster.
e2e-cleanup:
	@k3d cluster delete $(E2E_CLUSTER) 2>/dev/null || true

# eBPF E2E targets (requires Linux or k3d with privileged containers)
E2E_EBPF_CLUSTER=kloak-ebpf-e2e

# Full eBPF e2e: setup + run + cleanup.
e2e-ebpf: e2e-ebpf-setup e2e-ebpf-run e2e-ebpf-cleanup

# Create k3d cluster, build and import kloak + demo-go images.
e2e-ebpf-setup:
	@which k3d > /dev/null || (echo "Error: k3d not found. Install with: brew install k3d" && exit 1)
	@echo "==> Creating k3d cluster '$(E2E_EBPF_CLUSTER)'..."
	@k3d cluster create $(E2E_EBPF_CLUSTER) --wait --timeout 120s 2>/dev/null || true
	@echo "==> Building kloak image..."
	@docker build -t $(DOCKER_IMAGE):$(E2E_IMAGE_TAG) .
	@echo "==> Building demo-go image..."
	@docker build -t kloak-demo-go:$(E2E_IMAGE_TAG) ./examples/demo-go/
	@echo "==> Importing images into k3d..."
	@k3d image import $(DOCKER_IMAGE):$(E2E_IMAGE_TAG) kloak-demo-go:$(E2E_IMAGE_TAG) -c $(E2E_EBPF_CLUSTER)
	@docker pull bitnami/kubectl:latest
	@k3d image import bitnami/kubectl:latest -c $(E2E_EBPF_CLUSTER)
	@echo "==> eBPF E2E environment ready."

# Run eBPF e2e tests against an existing k3d cluster (use after e2e-ebpf-setup).
e2e-ebpf-run:
	KUBECONFIG=$$(k3d kubeconfig write $(E2E_EBPF_CLUSTER)) \
	KLOAK_E2E_OVERLAY=e2e-ebpf \
	$(GOTEST) -v -timeout 600s -tags=e2e_ebpf -count=1 ./test/e2e/

# Tear down eBPF e2e k3d cluster.
e2e-ebpf-cleanup:
	@k3d cluster delete $(E2E_EBPF_CLUSTER) 2>/dev/null || true

clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -f $(EBPF_PKG)/tlsuprobe_bpfel.go $(EBPF_PKG)/tlsuprobe_bpfeb.go
	rm -f $(EBPF_PKG)/tlsuprobe_bpfel.o $(EBPF_PKG)/tlsuprobe_bpfeb.o

deps:
	$(GOMOD) download
	$(GOMOD) tidy

docker-build: build
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

run: build
	./$(BUILD_DIR)/$(BINARY_NAME)

# ============================================================================
# eBPF generation targets
# ============================================================================

# Generate eBPF code - depends on BPF sources and vmlinux.h
generate-ebpf: $(BPF_SOURCES) $(BPF_DIR)/vmlinux.h lima-ensure
	@echo "Generating eBPF code..."
	@if [ "$$(uname)" = "Linux" ]; then \
		cd $(EBPF_PKG) && $(GOGENERATE); \
	else \
		echo "Using Lima VM for eBPF generation..."; \
		$(MAKE) lima-exec CMD="cd $(LIMA_WORKDIR)/$(EBPF_PKG) && go generate"; \
	fi
	@echo "eBPF generation complete."

# Generate vmlinux.h from kernel BTF - depends on Lima
$(BPF_DIR)/vmlinux.h: lima-ensure
	@echo "Generating vmlinux.h from kernel BTF..."
	@if [ "$$(uname)" = "Linux" ]; then \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@; \
	else \
		$(MAKE) lima-exec CMD="bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(LIMA_WORKDIR)/$@"; \
	fi

generate-vmlinux: $(BPF_DIR)/vmlinux.h

# ============================================================================
# Lima VM targets (for eBPF development on macOS)
# ============================================================================

# Check if Lima is installed
lima-check:
	@which limactl > /dev/null || (echo "Error: limactl not found. Install with: brew install lima" && exit 1)

# Ensure Lima VM is running (idempotent)
lima-ensure: lima-check $(LIMA_CONFIG)
	@if [ "$$(uname)" = "Linux" ]; then \
		exit 0; \
	elif ! limactl list 2>/dev/null | grep -q "^$(LIMA_VM)"; then \
		echo "Creating Lima VM '$(LIMA_VM)'..."; \
		limactl start --name=$(LIMA_VM) $(LIMA_CONFIG); \
	elif limactl list | grep "^$(LIMA_VM)" | grep -q "Stopped"; then \
		echo "Starting Lima VM '$(LIMA_VM)'..."; \
		limactl start $(LIMA_VM); \
	fi

# Start Lima VM for eBPF development
lima-start: lima-check $(LIMA_CONFIG)
	@if ! limactl list 2>/dev/null | grep -q "^$(LIMA_VM)"; then \
		echo "Creating Lima VM '$(LIMA_VM)'..."; \
		limactl start --name=$(LIMA_VM) $(LIMA_CONFIG); \
	elif limactl list | grep "^$(LIMA_VM)" | grep -q "Stopped"; then \
		echo "Starting Lima VM '$(LIMA_VM)'..."; \
		limactl start $(LIMA_VM); \
	else \
		echo "Lima VM '$(LIMA_VM)' is already running"; \
	fi

# Stop Lima VM
lima-stop:
	@limactl stop $(LIMA_VM) 2>/dev/null || true

# Delete Lima VM
lima-delete: lima-stop
	@limactl delete $(LIMA_VM) 2>/dev/null || true

# Shell into Lima VM
lima-shell: lima-ensure
	limactl shell $(LIMA_VM)

# Execute command in Lima VM (uses login shell for proper PATH)
lima-exec: lima-ensure
	@limactl shell $(LIMA_VM) -- bash -lc '$(CMD)'

# ============================================================================
# Help
# ============================================================================

help:
	@echo "Kloak Makefile - Kubernetes eBPF HTTPS Interceptor"
	@echo ""
	@echo "Build targets:"
	@echo "  build           - Build the kloak binary (native)"
	@echo "  build-linux     - Build for Linux (uses Lima on macOS)"
	@echo "  test            - Run unit tests"
	@echo "  test-linux      - Run tests in Linux VM"
	@echo "  e2e             - Full e2e: setup + run + cleanup"
	@echo "  e2e-setup       - Create k3d cluster and import images"
	@echo "  e2e-run         - Run e2e tests (requires e2e-setup first)"
	@echo "  e2e-cleanup     - Delete e2e k3d cluster"
	@echo "  e2e-ebpf        - Full eBPF e2e: setup + run + cleanup"
	@echo "  e2e-ebpf-setup  - Create k3d cluster with kloak + demo-go images"
	@echo "  e2e-ebpf-run    - Run eBPF e2e tests (requires e2e-ebpf-setup)"
	@echo "  e2e-ebpf-cleanup - Delete eBPF e2e k3d cluster"
	@echo "  clean           - Clean build artifacts"
	@echo "  deps            - Download and tidy dependencies"
	@echo "  docker-build    - Build Docker image"
	@echo "  run             - Build and run locally"
	@echo ""
	@echo "eBPF targets:"
	@echo "  generate-ebpf   - Generate eBPF Go bindings (uses Lima on macOS)"
	@echo "  generate-vmlinux - Generate vmlinux.h from kernel BTF"
	@echo ""
	@echo "Lima VM targets (for eBPF on macOS):"
	@echo "  lima-start      - Start the Lima VM"
	@echo "  lima-stop       - Stop the Lima VM"
	@echo "  lima-delete     - Delete the Lima VM"
	@echo "  lima-shell      - Open shell in Lima VM"
	@echo "  lima-ensure     - Ensure VM is running (idempotent)"
