.PHONY: all build build-linux test test-linux clean deps docker-build \
        generate-ebpf generate-vmlinux run help \
        lima-start lima-stop lima-delete lima-shell lima-exec lima-check

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod
GOGENERATE=$(GOCMD) generate

# Binary names
BINARY_NAME=bouncer
WEBHOOK_BINARY=bouncer-webhook

# Build directories
BUILD_DIR=bin
CMD_DIR=cmd
BPF_DIR=bpf
EBPF_PKG=pkg/ebpf

# Source files
GO_SOURCES=$(shell find . -name '*.go' -not -path './vendor/*')
BPF_SOURCES=$(wildcard $(BPF_DIR)/*.c $(BPF_DIR)/*.h)
EBPF_GENERATED=$(EBPF_PKG)/redirect_bpfel.go $(EBPF_PKG)/redirect_bpfeb.go

# Docker
DOCKER_IMAGE=bouncer
DOCKER_TAG=latest

# Lima VM
LIMA_VM=bouncer
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
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)/bouncer

# Build for Linux (cross-compile or via Lima)
build-linux: lima-ensure
	@if [ "$$(uname)" = "Linux" ]; then \
		GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-linux ./$(CMD_DIR)/bouncer; \
	else \
		$(MAKE) lima-exec CMD="cd $(LIMA_WORKDIR) && go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux ./$(CMD_DIR)/bouncer"; \
	fi

test: deps
	$(GOTEST) -v ./...

# Run tests in Linux VM (for eBPF tests) - depends on Lima running
test-linux: lima-ensure
	$(MAKE) lima-exec CMD="cd $(LIMA_WORKDIR) && go test -v ./..."

clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -f $(EBPF_PKG)/redirect_bpfel.go $(EBPF_PKG)/redirect_bpfeb.go
	rm -f $(EBPF_PKG)/redirect_bpfel.o $(EBPF_PKG)/redirect_bpfeb.o

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
	@echo "Bouncer Makefile - Kubernetes eBPF HTTPS Interceptor"
	@echo ""
	@echo "Build targets:"
	@echo "  build           - Build the bouncer binary (native)"
	@echo "  build-linux     - Build for Linux (uses Lima on macOS)"
	@echo "  test            - Run tests"
	@echo "  test-linux      - Run tests in Linux VM"
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
