# Copyright 2025 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_TARGET: all
BIN := ratsd

.PHONY: all
all: build

.PHONY: build
build:
	go build -o $(BIN) ./cmd

.PHONY: clean
clean:
	rm -f $(BIN) 
