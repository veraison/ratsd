# Copyright 2025 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_TARGET: all
BIN := ratsd

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

.PHONY: test
test:
	go test -v --cover --race ./...

.PHONY: clean clean-sa clean-la
clean: clean-sa clean-la

clean-sa:
	make -C attesters/ clean

clean-la:
	rm -f $(BIN) 

.PHONY: clean-certs
clean-certs:
	./gen-certs clean
