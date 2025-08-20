// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package plugin

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/hashicorp/go-plugin"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type unknownPluginErr struct {
	Name string
}

func (o unknownPluginErr) Error() string {
	return fmt.Sprintf("unknown plugin: %s", o.Name)
}

type GoPluginLoader struct {
	Location string

	logger       *zap.SugaredLogger
	loadedByName map[string]*PluginContext
	pluginChecksum map[string][]byte

	// This gets specified as Plugins when creating a new go-plugin client.
	pluginMap map[string]plugin.Plugin
}

func NewGoPluginLoader(logger *zap.SugaredLogger) *GoPluginLoader {
	return &GoPluginLoader{logger: logger}
}

func CreateGoPluginLoader(
	dir string,
	logger *zap.SugaredLogger,
) (*GoPluginLoader, error) {
	loader := NewGoPluginLoader(logger)
	err := loader.Init(dir)
	return loader, err
}

func (o *GoPluginLoader) Init(dir string) error {
	o.pluginMap = make(map[string]plugin.Plugin)
	o.loadedByName = make(map[string]*PluginContext)
	o.pluginChecksum = make(map[string][]byte)
	o.Location = dir

	return nil
}

func (o *GoPluginLoader) Close() {
	for _, plugin := range o.loadedByName {
		plugin.Close()
	}
}

func (o *GoPluginLoader) SetChecksum(v *viper.Viper) error {
	for _, name := range v.AllKeys() {
		sha256sum := v.Get(name)
		switch t := sha256sum.(type) {
		case string:
			o.logger.Debugw("registered plugin checksum",
				"name", name,
				"checksum", t,
			)

			checksum, err := hex.DecodeString(t)
			if err != nil {
				return fmt.Errorf(
					"failed to load sha256 checksum for %s: %v",
					name, err,
				)
			}

			o.pluginChecksum[name] = checksum
		default:
			return fmt.Errorf(
				"invalid checksum for plugin %q: expected string, got %T",
				name, t,
			)
		}
	}

	return nil
}

func RegisterGoPluginUsing(loader *GoPluginLoader, name string) error {
	if _, ok := loader.pluginMap[name]; ok {
		return fmt.Errorf("plugin for %q is already registred", name)
	}
	loader.pluginMap[name] = &Plugin{}

	return nil
}

func DiscoverGoPluginUsing(o *GoPluginLoader) error {
	if o.Location == "" {
		return errors.New("plugin manager has not been initialized")
	}

	o.logger.Debugw("discovering plugins", "location", o.Location)
	pluginPaths, err := plugin.Discover("*.plugin", o.Location)
	if err != nil {
		return err
	}

	for _, path := range pluginPaths {
		pluginContext, err := createPluginContext(o, path, o.logger)
		if err != nil {
			var upErr unknownPluginErr
			if errors.As(err, &upErr) {
				o.logger.Debugw("plugin not found", "name", upErr.Name, "path", path)
				continue
			} else {
				return err
			}
		}

		pluginName := pluginContext.Name
		if existing, ok := o.loadedByName[pluginName]; ok {
			return fmt.Errorf(
				"plugin %q provided by two sources: [%s] and [%s]",
				pluginName,
				existing.Path,
				pluginContext.Path,
			)
		}
		o.loadedByName[pluginName] = pluginContext
	}

	return nil
}

func GetGoPluginHandleByNameUsing(ldr *GoPluginLoader, name string) (IPluggable, error) {
	plugged, ok := ldr.loadedByName[name]
	if !ok {
		return nil, fmt.Errorf(
			"plugin %s not found", name)
	}

	return plugged.Handle, nil
}
