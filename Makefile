# Copyright 2025 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_GOAL := all

SHELL := /bin/bash

BIN := ratsd

GOMODS := .
GOMODS += ratsd-token
GOMODS += ratsd-token/v2

.PHONY: all
all: generate build

.PHONY: gen-certs
gen-certs:
	./gen-certs create

.PHONY: generate
generate:
	go generate ./...

.PHONY: build build-sa build-la
build: build-sa build-la

build-sa:
	make -C attesters/

build-la:
	go build -o $(BIN) -buildmode=pie ./cmd

GOLINT ?= golangci-lint
GOLINT_ARGS ?= run

.PHONY: lint
lint:
	set -e; for mod in $(GOMODS); do \
		(cd $$mod && $(GOLINT) $(GOLINT_ARGS)); \
	done

ifeq ($(MAKECMDGOALS),test)
GOTEST_ARGS ?= -v -race
GOTEST_PKGS ?= ./...
else
  ifeq ($(MAKECMDGOALS),test-cover)
  GOTEST_ARGS ?= -short -cover
  GOTEST_PKGS ?= $$(go list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' ./...)
  endif
endif

COVER_THRESHOLD := $(shell sed -n "s/^ *min-coverage: '\(.*\)'/≥\1%/p" .github/workflows/ci-go-cover.yml)

.PHONY: test test-cover
test test-cover:
	set -e; for mod in $(GOMODS); do \
		(cd $$mod && go test $(GOTEST_ARGS) $(GOTEST_PKGS)); \
	done

.PHONY: presubmit
presubmit:
	@echo
	@echo ">>> Check that the reported coverage figures are $(COVER_THRESHOLD)"
	@echo
	$(MAKE) test-cover
	@echo
	@echo ">>> Fix any lint error"
	@echo
	$(MAKE) lint

.PHONY: clean clean-sa clean-la
clean: clean-sa clean-la

clean-sa:
	make -C attesters/ clean

clean-la:
	rm -f $(BIN) 

.PHONY: clean-certs
clean-certs:
	./gen-certs clean

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  * all:        generate sources and build ratsd and the attester plugins"
	@echo "  * generate:   regenerate the protobuf, API and mock sources"
	@echo "  * build:      build ratsd and the attester plugins"
	@echo "  * test:       run unit tests for the modules in $(GOMODS)"
	@echo "  * test-cover: run unit tests and measure coverage for $(GOMODS)"
	@echo "  * lint:       lint sources using .golangci.yml"
	@echo "  * presubmit:  check you are ready to push your local branch to remote"
	@echo "  * clean:      remove build artifacts"
	@echo "  * gen-certs:  create test certificates"
	@echo "  * help:       print this menu"
