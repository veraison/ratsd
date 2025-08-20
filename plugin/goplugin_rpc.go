// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package plugin

import (
	"context"

	"github.com/veraison/ratsd/proto/compositor"
	"github.com/veraison/services/log"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/emptypb"
)

type GRPCServer struct {
	compositor.UnimplementedCompositorServer
	Impl IPluggable
}

func (s *GRPCServer) GetSubAttesterID(ctx context.Context, e *emptypb.Empty) (*compositor.SubAttesterIDOut, error) {
	return s.Impl.GetSubAttesterID(), nil
}

func (s *GRPCServer) GetSupportedFormats(ctx context.Context, e *emptypb.Empty) (*compositor.SupportedFormatsOut, error) {
	return s.Impl.GetSupportedFormats(), nil
}

func (s *GRPCServer) GetEvidence(ctx context.Context, in *compositor.EvidenceIn) (*compositor.EvidenceOut, error) {
	return s.Impl.GetEvidence(in), nil
}

func (s *GRPCServer) GetOptions(ctx context.Context, e *emptypb.Empty) (*compositor.OptionsOut, error) {
	return s.Impl.GetOptions(), nil
}

type GRPCClient struct {
	client compositor.CompositorClient
}

func (c *GRPCClient) GetSubAttesterID() *compositor.SubAttesterIDOut {
	resp, err := c.client.GetSubAttesterID(context.Background(), &emptypb.Empty{})
	if err != nil {
		return &compositor.SubAttesterIDOut{
			Status: &compositor.Status{Result: false, Error: err.Error()},
		}
	}

	return resp
}

func (c *GRPCClient) GetSupportedFormats() *compositor.SupportedFormatsOut {
	resp, err := c.client.GetSupportedFormats(context.Background(), &emptypb.Empty{})
	if err != nil {
		return &compositor.SupportedFormatsOut{
			Status: &compositor.Status{Result: false, Error: err.Error()},
		}
	}

	return resp
}

func (c *GRPCClient) GetEvidence(in *compositor.EvidenceIn) *compositor.EvidenceOut {
	resp, err := c.client.GetEvidence(context.Background(), in)
	if err != nil {
		return &compositor.EvidenceOut{
			Status: &compositor.Status{Result: false, Error: err.Error()},
		}
	}

	return resp
}

func (c *GRPCClient) GetOptions() *compositor.OptionsOut {
	resp, err := c.client.GetOptions(context.Background(), &emptypb.Empty{})
	if err != nil {
		return &compositor.OptionsOut{
			Status: &compositor.Status{Result: false, Error: err.Error()},
		}
	}

	return resp
}

var logger *zap.SugaredLogger

func init() {
}

// note: we cannot simply initialize logger
func getLogger() *zap.SugaredLogger {
	if logger == nil {
		logger = log.Named("plugin.rpc")
	}
	return logger
}
