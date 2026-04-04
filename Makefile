.PHONY: all build build-linux test test-linux test-bpf-helpers e2e e2e-setup e2e-run e2e-cleanup \
        clean deps docker-build generate-ebpf generate-vmlinux run help \
        lima-start lima-stop lima-delete lima-shell lima-exec lima-check \
        lima-k3d-ensure lima-k3d-shell lima-k3d-e2e-setup lima-k3d-e2e-run lima-k3d-e2e lima-k3d-stop lima-k3d-delete

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

# Run eBPF helper unit tests (pure C, no Linux/BPF required)
test-bpf-helpers:
	gcc -Wall -Werror -o /tmp/helpers_test pkg/ebpf/bpf/helpers_test.c
	/tmp/helpers_test

# E2E cluster and image configuration
E2E_CLUSTER=kloak-e2e
E2E_IMAGE_TAG=e2e

# Full e2e: setup cluster, run tests, tear down.
e2e: e2e-setup e2e-run e2e-cleanup

# Create k3d cluster with BPF mounts, build and import all images.
e2e-setup:
	@which k3d > /dev/null || (echo "Error: k3d not found. Install with: brew install k3d" && exit 1)
	@mountpoint -q /sys/kernel/tracing 2>/dev/null || sudo mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
	@echo "==> Creating k3d cluster '$(E2E_CLUSTER)' with BPF mounts..."
	@k3d cluster create $(E2E_CLUSTER) --wait --timeout 120s \
		--volume /sys/kernel/btf:/sys/kernel/btf:ro@server:0 \
		--volume /sys/fs/bpf:/sys/fs/bpf:rw@server:0 \
		--volume /sys/kernel/tracing:/sys/kernel/tracing:rw@server:0 \
		2>/dev/null || true
	@echo "==> Building kloak image..."
	@docker build -t $(DOCKER_IMAGE):$(E2E_IMAGE_TAG) .
	@echo "==> Building demo images..."
	@docker build -t kloak-demo-go:$(E2E_IMAGE_TAG) -t kloak-demo-go:latest ./examples/demo-go/
	@docker build -t kloak-demo-python:latest ./examples/demo-python/
	@docker build -t kloak-demo-js:latest ./examples/demo-js/
	@docker build -t kloak-demo-go-boring:latest ./examples/demo-go-boring/
	@docker build -t kloak-demo-gnutls:latest ./examples/demo-gnutls/
	@docker build -t kloak-demo-python-raw-tls:latest ./examples/demo-python-raw-tls/
	@docker build -t kloak-tls-echo:latest ./test/e2e/tls-echo-server/
	@echo "==> Importing images into k3d (via tar to avoid pipe EOF)..."
	@mkdir -p /tmp/k3d-images
	@for img in $(DOCKER_IMAGE):$(E2E_IMAGE_TAG) kloak-demo-go:latest kloak-demo-python:latest \
		kloak-demo-js:latest kloak-demo-go-boring:latest kloak-demo-gnutls:latest \
		kloak-demo-python-raw-tls:latest kloak-tls-echo:latest; do \
		echo "  Importing $$img..."; \
		docker save $$img -o /tmp/k3d-images/$$(echo $$img | tr ':/' '__').tar && \
		k3d image import /tmp/k3d-images/$$(echo $$img | tr ':/' '__').tar -c $(E2E_CLUSTER); \
	done
	@rm -rf /tmp/k3d-images
	@echo "==> E2E environment ready."

# Run e2e tests (including eBPF) against an existing k3d cluster.
e2e-run:
	KUBECONFIG=$$(k3d kubeconfig write $(E2E_CLUSTER)) \
	$(GOTEST) -v -timeout 900s -tags=e2e_ebpf -count=1 ./test/e2e/

# Run e2e tests against the current kube context.
# Builds images, pushes to ttl.sh (anonymous ephemeral registry, 2h TTL),
# and runs tests with E2E_REGISTRY so images are pulled from there.
# Set E2E_REGISTRY to use a different registry (e.g. localhost:5000).
# WARNING: This will helm install/uninstall kloak in kloak-system and
# create/delete a kloak-e2e namespace.
# Usage: make e2e-local
E2E_TTL_TAG ?= kloak-$(shell date +%s)
E2E_REGISTRY ?= ttl.sh/$(E2E_TTL_TAG)

e2e-local: e2e-local-push e2e-local-run

e2e-local-push:
	@echo "==> Building and pushing images to $(E2E_REGISTRY) ..."
	@docker build -t $(E2E_REGISTRY)/kloak:e2e .
	@docker push $(E2E_REGISTRY)/kloak:e2e
	@for demo in demo-go demo-python demo-js demo-go-boring demo-gnutls demo-python-raw-tls; do \
		echo "  Pushing kloak-$$demo..."; \
		docker build -t $(E2E_REGISTRY)/kloak-$$demo:latest ./examples/$$demo/ && \
		docker push $(E2E_REGISTRY)/kloak-$$demo:latest; \
	done
	@docker build -t $(E2E_REGISTRY)/kloak-tls-echo:latest ./test/e2e/tls-echo-server/
	@docker push $(E2E_REGISTRY)/kloak-tls-echo:latest
	@echo "==> All images pushed."

# E2E_RUN: optional -run filter (e.g. E2E_RUN=TestCipherSuites make e2e-local)
E2E_RUN ?=

e2e-local-run:
	E2E_REGISTRY=$(E2E_REGISTRY) \
	$(GOTEST) -v -timeout 900s -tags=e2e_ebpf -count=1 $(if $(E2E_RUN),-run $(E2E_RUN)) ./test/e2e/

# Tear down e2e k3d cluster.
e2e-cleanup:
	@k3d cluster delete $(E2E_CLUSTER) 2>/dev/null || true

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

# Generate eBPF code - depends on BPF sources and vmlinux.h.
# KLOAK_TARGET_ARCH defaults to arm64 (Lima VM). Set to x86 for amd64 builds.
generate-ebpf: $(BPF_SOURCES) $(BPF_DIR)/vmlinux.h lima-ensure
	@echo "Generating eBPF code (arch=$${KLOAK_TARGET_ARCH:-arm64})..."
	@if [ "$$(uname)" = "Linux" ]; then \
		cd $(EBPF_PKG) && $(GOGENERATE); \
	else \
		echo "Using Lima VM for eBPF generation..."; \
		$(MAKE) lima-exec CMD="cd $(LIMA_WORKDIR)/$(EBPF_PKG) && KLOAK_TARGET_ARCH=$${KLOAK_TARGET_ARCH:-arm64} go generate"; \
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
# Lima k3d targets (for e2e testing on ARM Mac)
# ============================================================================

LIMA_K3D_VM=kloak-k3d
LIMA_K3D_CONFIG=lima-k3d.yaml

# Ensure k3d Lima VM is running
lima-k3d-ensure: lima-check $(LIMA_K3D_CONFIG)
	@if ! limactl list 2>/dev/null | grep -q "^$(LIMA_K3D_VM)"; then \
		echo "Creating Lima k3d VM '$(LIMA_K3D_VM)'..."; \
		limactl start --name=$(LIMA_K3D_VM) $(LIMA_K3D_CONFIG); \
	elif limactl list | grep "^$(LIMA_K3D_VM)" | grep -q "Stopped"; then \
		echo "Starting Lima k3d VM '$(LIMA_K3D_VM)'..."; \
		limactl start $(LIMA_K3D_VM); \
	fi

# Shell into k3d Lima VM
lima-k3d-shell: lima-k3d-ensure
	limactl shell $(LIMA_K3D_VM)

# Run e2e setup inside k3d Lima VM
lima-k3d-e2e-setup: lima-k3d-ensure
	limactl shell $(LIMA_K3D_VM) -- bash -lc 'sg docker -c "cd $(LIMA_WORKDIR) && make e2e-setup"'

# Run e2e tests inside k3d Lima VM
lima-k3d-e2e-run: lima-k3d-ensure
	limactl shell $(LIMA_K3D_VM) -- bash -lc 'sg docker -c "cd $(LIMA_WORKDIR) && make e2e-run"'

# Full e2e inside k3d Lima VM
lima-k3d-e2e: lima-k3d-e2e-setup lima-k3d-e2e-run

# Stop k3d Lima VM
lima-k3d-stop:
	@limactl stop $(LIMA_K3D_VM) 2>/dev/null || true

# Delete k3d Lima VM
lima-k3d-delete: lima-k3d-stop
	@limactl delete $(LIMA_K3D_VM) 2>/dev/null || true

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
	@echo "  e2e             - Full e2e: setup + run + cleanup (includes eBPF tests)"
	@echo "  e2e-setup       - Create k3d cluster with BPF mounts and import images"
	@echo "  e2e-run         - Run e2e tests (requires e2e-setup first)"
	@echo "  e2e-cleanup     - Delete e2e k3d cluster"
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
	@echo ""
	@echo "Lima k3d targets (for e2e on ARM Mac):"
	@echo "  lima-k3d-shell  - Shell into k3d Lima VM"
	@echo "  lima-k3d-e2e    - Full e2e: setup + run inside Lima k3d VM"
	@echo "  lima-k3d-e2e-setup - Create k3d cluster inside Lima VM"
	@echo "  lima-k3d-e2e-run   - Run e2e tests inside Lima VM"
	@echo "  lima-k3d-stop   - Stop k3d Lima VM"
	@echo "  lima-k3d-delete - Delete k3d Lima VM"
