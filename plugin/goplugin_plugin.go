// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package plugin

import (
	"context"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	"github.com/veraison/ratsd/proto/compositor"
)

const (
	pluginType = "subattester"
)

var handshakeConfig = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "RATSD_PLUGIN",
	MagicCookieValue: "RATSD",
}

type Plugin struct {
	plugin.Plugin
	Impl IPluggable
}

func (p *Plugin) GRPCServer(b *plugin.GRPCBroker, s *grpc.Server) error {
	compositor.RegisterCompositorServer(s, &GRPCServer{Impl: p.Impl})
	return nil
}

func (p *Plugin) GRPCClient(ctx context.Context, b *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: compositor.NewCompositorClient(c)}, nil
}

var pluginMap = map[string]plugin.Plugin{}

func RegisterImplementation(i IPluggable) {
	pluginMap[pluginType] = &Plugin{
		Impl: i,
	}
}

func Serve() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: handshakeConfig,
		Plugins:         pluginMap,
		GRPCServer:      plugin.DefaultGRPCServer,
	})
}
