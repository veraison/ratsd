// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package plugin

//go:generate mockgen -destination=../api/mocks/imanager.go -package=mocks github.com/veraison/ratsd/plugin IManager

type IManager interface {
	Init() error
	Close() error
	LookupByName(string) (IPluggable, error)
	GetPluginList() []string
}
