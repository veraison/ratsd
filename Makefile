# Copyright 2025 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_TARGET: all
BIN := ratsd

.PHONY: all
all: generate build test

.PHONY: gen-certs
gen-certs:
	./gen-certs create

.PHONY: generate
generate:
	go generate ./...

.PHONY: build
build:
	go build -o $(BIN) -buildmode=pie ./cmd

.PHONY: test
test:
	go test -v github.com/veraison/ratsd/api
	go test -v github.com/veraison/ratsd/tokens

.PHONY: clean
clean:
	rm -f $(BIN) 

.PHONY: clean-certs
clean-certs:
	./gen-certs clean
