# Copyright 2025 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0

ifndef SUBDIR
$(error SUBDIR must be set when including subdir.mk)
endif

.DEFAULT_GOAL := build
MAKECMDGOALS ?= $(.DEFAULT_GOAL)

.PHONY: build $(SUBDIR)
build: $(SUBDIR)

$(SUBDIR): ; make -C $@
