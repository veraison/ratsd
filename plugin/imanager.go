// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package plugin

type IManager interface {
	Init() error
	Close() error
	LookupByName(string) (IPluggable, error)
	GetPluginList() []string
}
