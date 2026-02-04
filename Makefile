.PHONY: build clean test docker-build

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Binary names
BINARY_NAME=bouncer
WEBHOOK_BINARY=bouncer-webhook

# Build directories
BUILD_DIR=bin
CMD_DIR=cmd

# Docker
DOCKER_IMAGE=bouncer
DOCKER_TAG=latest

all: build

build: $(BUILD_DIR)/$(BINARY_NAME)

$(BUILD_DIR)/$(BINARY_NAME): cmd/bouncer/main.go
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)/bouncer

test:
	$(GOTEST) -v ./...

clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)

deps:
	$(GOMOD) download
	$(GOMOD) tidy

docker-build:
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

# Generate eBPF code (future iteration)
generate-ebpf:
	@echo "eBPF generation will be added in Iteration 3"

# Run locally (for development)
run: build
	./$(BUILD_DIR)/$(BINARY_NAME)

help:
	@echo "Available targets:"
	@echo "  build        - Build the bouncer binary"
	@echo "  test         - Run tests"
	@echo "  clean        - Clean build artifacts"
	@echo "  deps         - Download and tidy dependencies"
	@echo "  docker-build - Build Docker image"
	@echo "  run          - Build and run locally"
