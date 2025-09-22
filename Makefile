# Copyright 2025 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_GOAL := all
BIN := ratsd

.PHONY: help
help:
	@echo "RATSD Makefile Commands:"
	@echo ""
	@echo "Building:"
	@echo "  all              Build everything (check deps, generate code, build binary and attesters)"
	@echo "  build            Build ratsd binary and all attesters"
	@echo "  build-sa         Build sub-attesters only"
	@echo "  build-la         Build ratsd binary only"
	@echo ""
	@echo "Code Generation:"
	@echo "  generate         Generate code from protobuf and OpenAPI specs"
	@echo "  install-tools    Install Go code generation tools (requires protoc)"
	@echo "  install-protoc   Install protoc compiler (requires sudo)"
	@echo "  setup-dev        Install protoc + Go tools (complete dev setup)"
	@echo ""
	@echo "Testing:"
	@echo "  test             Run all tests"
	@echo ""
	@echo "Certificates:"
	@echo "  gen-certs        Generate TLS certificates"
	@echo "  clean-certs      Clean generated certificates"
	@echo ""
	@echo "Cleanup:"
	@echo "  clean            Clean all build artifacts"
	@echo "  clean-sa         Clean sub-attester build artifacts"
	@echo "  clean-la         Clean ratsd binary"
	@echo ""
	@echo "Dependency Checks:"
	@echo "  check-protoc          Check if protoc is installed"
	@echo "  check-generate-deps   Check if all code generation tools are available"
	@echo ""
	@echo "Prerequisites:"
	@echo "  - Install protoc: sudo apt-get install protobuf-compiler (Ubuntu/Debian)"
	@echo "  - Run 'make install-tools' to install Go code generation tools"
	@echo "  - See README.md for detailed installation instructions"
	@echo ""

.PHONY: all
all: check-protoc generate build

.PHONY: gen-certs
gen-certs:
	./gen-certs create

.PHONY: generate
generate: check-generate-deps
	go generate ./...

.PHONY: check-generate-deps
check-generate-deps: check-protoc
	@echo "Checking for required code generation tools..."
	@which protoc-gen-go > /dev/null 2>&1 || { \
		echo "ERROR: protoc-gen-go is not installed."; \
		echo "Please run 'make install-tools' first."; \
		exit 1; \
	}
	@which protoc-gen-go-grpc > /dev/null 2>&1 || { \
		echo "ERROR: protoc-gen-go-grpc is not installed."; \
		echo "Please run 'make install-tools' first."; \
		exit 1; \
	}
	@echo "All code generation dependencies are available."

.PHONY: build build-sa build-la
build: build-sa build-la

build-sa:
	make -C attesters/

build-la:
	go build -o $(BIN) -buildmode=pie ./cmd

.PHONY: test
test:
	go test -v --cover --race ./...

.PHONY: clean clean-sa clean-la
clean: clean-sa clean-la

clean-sa:
	make -C attesters/ clean

clean-la:
	rm -f $(BIN) 

.PHONY: install-tools
install-tools: check-protoc
	go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen
	go install google.golang.org/protobuf/cmd/protoc-gen-go
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	go install go.uber.org/mock/mockgen

.PHONY: check-protoc
check-protoc:
	@echo "Checking for protoc..."
	@which protoc > /dev/null 2>&1 || { \
		echo "ERROR: protoc (Protocol Buffer Compiler) is not installed or not in PATH."; \
		echo ""; \
		echo "Please install protoc using one of the following methods:"; \
		echo ""; \
		echo "Ubuntu/Debian:"; \
		echo "  sudo apt-get update && sudo apt-get install -y protobuf-compiler"; \
		echo ""; \
		echo "RHEL/CentOS:"; \
		echo "  sudo yum install -y protobuf-compiler"; \
		echo ""; \
		echo "Fedora:"; \
		echo "  sudo dnf install -y protobuf-compiler"; \
		echo ""; \
		echo "macOS:"; \
		echo "  brew install protobuf"; \
		echo ""; \
		echo "Or download from: https://github.com/protocolbuffers/protobuf/releases"; \
		echo ""; \
		exit 1; \
	}
	@echo "protoc found: $$(which protoc)"

.PHONY: install-protoc
install-protoc:
	@echo "Attempting to install protoc..."
	@if command -v apt-get >/dev/null 2>&1; then \
		echo "Detected apt-get (Ubuntu/Debian). Installing protobuf-compiler..."; \
		sudo apt-get update && sudo apt-get install -y protobuf-compiler; \
	elif command -v yum >/dev/null 2>&1; then \
		echo "Detected yum (RHEL/CentOS). Installing protobuf-compiler..."; \
		sudo yum install -y protobuf-compiler; \
	elif command -v dnf >/dev/null 2>&1; then \
		echo "Detected dnf (Fedora). Installing protobuf-compiler..."; \
		sudo dnf install -y protobuf-compiler; \
	elif command -v brew >/dev/null 2>&1; then \
		echo "Detected brew (macOS). Installing protobuf..."; \
		brew install protobuf; \
	else \
		echo "Unable to detect package manager. Please install protoc manually."; \
		echo "See README.md for installation instructions."; \
		exit 1; \
	fi
	@echo "protoc installation completed. Verifying..."
	@which protoc || { echo "Installation failed. Please install protoc manually."; exit 1; }

.PHONY: setup-dev
setup-dev: install-protoc install-tools
	@echo "Development environment setup complete!"
	@echo "You can now run 'make' to build RATSD."

.PHONY: clean-certs
clean-certs:
	./gen-certs clean
