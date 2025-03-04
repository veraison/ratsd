# Copyright 2025 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_GOAL := all

ifndef PLUGIN
	$(error PLUGIN must be set when including plugin.mk)
endif

ifdef DEBUG
	DFLAGS := -gcflags='all=-N -l'
else
	DFLAGS :=
endif

$(PLUGIN): $(SRCS) ; CGO_ENABLED=1 go build $(DFLAGS) -o $(PLUGIN)

.PHONY: all
all: $(PLUGIN)
