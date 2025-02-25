# Copyright 2025 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_TARGET: all
BIN := ratsd

.PHONY: all
all: generate build-all

.PHONY: gen-certs
gen-certs:
	./gen-certs create

.PHONY: generate
generate:
	go generate ./...

.PHONY: build-all build
build-all: build-attesters build

build-attesters:
	make -C attesters/

build:
	go build -o $(BIN) -buildmode=pie ./cmd

.PHONY: test
test:
	go test -v --cover --race ./...

.PHONY: clean-all clean
clean-all: clean-attesters clean

clean-attesters:
	make -C attesters/ clean

clean:
	rm -f $(BIN) 

.PHONY: clean-certs
clean-certs:
	./gen-certs clean
