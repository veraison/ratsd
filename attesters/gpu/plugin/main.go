// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"github.com/veraison/ratsd/attesters/gpu"
	"github.com/veraison/ratsd/plugin"
)

func main() {
	plugin.RegisterImplementation(gpu.NewPlugin())
	plugin.Serve()
}
