# Copyright 2025 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_TARGET: all
BIN := ratsd

.PHONY: all
all: generate build

.PHONY: generate
generate:
	go generate ./api

.PHONY: build
build:
	go build -o $(BIN) -buildmode=pie ./cmd

.PHONY: clean
clean:
	rm $(BIN) 
