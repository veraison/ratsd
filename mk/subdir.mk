# Copyright 2025 Contributors to the Veraison project.
# SPDX-License-Identifier: Apache-2.0

ifndef SUBDIR
	$(error SUBDIR must be set when including subdir.mk)
endif

.DEFAULT_GOAL := all
MAKECMDGOALS ?= $(.DEFAULT_GOAL)

.PHONY: all $(SUBDIR) test
build: $(SUBDIR)

$(SUBDIR): ; make -C $@
