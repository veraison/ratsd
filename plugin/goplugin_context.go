// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package plugin

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/hashicorp/go-plugin"
	"github.com/veraison/services/log"
	"go.uber.org/zap"
)

// PluginContext is a generic for handling ratsd attesters. It is
// parameterised on the IPluggable interface it handles.
type PluginContext struct {
	// Path to the exectable binary containing the plugin implementation
	Path string

	// Name of this plugin
	Name string

	// Version of this plugin
	Version string

	// Handle is actual RPC interface to the plugin implementation.
	Handle IPluggable

	// go-plugin client
	client *plugin.Client
}

func (o PluginContext) Close() {
	if o.client != nil {
		o.client.Kill()
	}
}

func createPluginContext(
	loader *GoPluginLoader,
	path string,
	logger *zap.SugaredLogger,
) (*PluginContext, error) {
	client := plugin.NewClient(
		&plugin.ClientConfig{
			HandshakeConfig:  handshakeConfig,
			Plugins:          loader.pluginMap,
			Cmd:              exec.Command(path),
			Logger:           log.NewInternalLogger(logger),
			AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		},
	)

	rpcClient, err := client.Client()
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf(
			"unable to create the RPC client for %s: %w",
			path, err,
		)
	}

	protocolClient, err := rpcClient.Dispense(pluginType)
	if err != nil {
		client.Kill()
		if strings.Contains(err.Error(), "unknown plugin") {
			return nil, unknownPluginErr{Name: pluginType}
		}
		return nil, fmt.Errorf("unable to dispense plugin %s: %w", path, err)
	}

	handle, ok := protocolClient.(IPluggable)
	if !ok {
		client.Kill()
		return nil, fmt.Errorf(
			"failed to retrieve handle for protocol client %T",
			protocolClient,
		)
	}

	blob := handle.GetSubAttesterID()
	if !blob.Status.Result {
		return nil, fmt.Errorf("failed to retrieve subattestr ID from %s", path)
	}

	return &PluginContext{
		Path:    path,
		Name:    blob.SubAttesterID.Name,
		Version: blob.SubAttesterID.Version,
		Handle:  handle,
		client:  client,
	}, nil
}
