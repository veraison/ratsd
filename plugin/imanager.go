// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package plugin

// IManager defines the interface for managing plugins
type IManager interface {
	// Init initializes the manager, and performing plugin discovery.
	Init() error

	// Close terminates the manager.
	Close() error

	// LookupByName returns a handle (implementation of the managed
	// interface) to the plugin with the specified name. If there is no
	// such plugin, an error is returned.
	LookupByName(string) (IPluggable, error)

	// GetPluginList returns a []string of the name for the plugins
	// that have been registered with the manager by discovered
	// plugins.
	GetPluginList() []string
}
