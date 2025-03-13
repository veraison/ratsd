// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"github.com/veraison/ratsd/attesters/mocktsm"
	"github.com/veraison/ratsd/plugin"
)

func main() {
	m := mocktsm.GetPlugin()
	plugin.RegisterImplementation(m)
	plugin.Serve()
}
