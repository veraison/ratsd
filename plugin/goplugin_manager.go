// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package plugin

import (
	"errors"

	"go.uber.org/zap"
)

var ErrNotFound = errors.New("plugin not found")

type GoPluginManager struct {
	loader *GoPluginLoader
	logger *zap.SugaredLogger
}

func NewGoPluginManager(loader *GoPluginLoader, logger *zap.SugaredLogger) *GoPluginManager {
	return &GoPluginManager{loader: loader, logger: logger}
}

func CreateGoPluginManager(dir string, logger *zap.SugaredLogger) (*GoPluginManager, error) {
	loader, err := CreateGoPluginLoader(dir, logger)
	if err != nil {
		return nil, err
	}

	return CreateGoPluginManagerWithLoader(loader, logger)
}

func CreateGoPluginManagerWithLoader(
	loader *GoPluginLoader,
	logger *zap.SugaredLogger,
) (*GoPluginManager, error) {
	manager := NewGoPluginManager(loader, logger)
	if err := manager.Init(); err != nil {
		return nil, err
	}

	return manager, nil
}

func (o *GoPluginManager) Init() error {
	err := RegisterGoPluginUsing(o.loader, pluginType)
	if err != nil {
		return err
	}
	return DiscoverGoPluginUsing(o.loader)
}

func (o *GoPluginManager) Close() error {
	o.loader.Close()
	return nil
}

func (o *GoPluginManager) LookupByName(name string) (IPluggable, error) {
	return GetGoPluginHandleByNameUsing(o.loader, name)
}

func (o *GoPluginManager) GetPluginList() []string {
	var registeredPlugin []string

	for name, _ := range o.loader.loadedByName {
		registeredPlugin = append(registeredPlugin, name)
	}

	return registeredPlugin
}
