// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package mocktsm

import (
	"fmt"

	"github.com/google/go-configfs-tsm/configfs/configfsi"
	"github.com/google/go-configfs-tsm/configfs/faketsm"
	"github.com/google/go-configfs-tsm/report"
	"github.com/veraison/ratsd/proto/compositor"
	"github.com/veraison/ratsd/tokens"
)

const (
	mediaType = "application/vnd.veraison.configfs-tsm+json"
	nonceSize = 64
)

var (
	sid = &compositor.SubAttesterID{
		Name:    "mock-tsm",
		Version: "1.0.0",
	}

	supportedFormats = []*compositor.Format{
		&compositor.Format{
			ContentType: mediaType,
			NonceSize:   nonceSize,
		},
	}

	statusSucceeded = &compositor.Status{Result: true, Error: ""}
)

type MockPlugin struct {
	client *faketsm.Client
}

func getEvidenceError(e error) *compositor.EvidenceOut {
	return &compositor.EvidenceOut{
		Status: &compositor.Status{
			Result: false, Error: e.Error(),
		},
	}
}

func (m *MockPlugin) GetSubAttesterID() *compositor.SubAttesterIDOut {
	return &compositor.SubAttesterIDOut{
		SubAttesterID: sid,
		Status:        statusSucceeded,
	}
}

func (m *MockPlugin) GetSupportedFormats() *compositor.SupportedFormatsOut {
	return &compositor.SupportedFormatsOut{
		Status:  statusSucceeded,
		Formats: supportedFormats,
	}
}

func (m *MockPlugin) GetEvidence(in *compositor.EvidenceIn) *compositor.EvidenceOut {
	if uint32(len(in.Nonce)) != nonceSize {
		errMsg := fmt.Errorf(
			"nonce size of the mockTSM attester should be %d, got %d",
			nonceSize, uint32(len(in.Nonce)))
		return getEvidenceError(errMsg)
	}

	if in.ContentType != mediaType {
		errMsg := fmt.Errorf(
			"no supported format in mock TSM plugin matches the requested format")
		return getEvidenceError(errMsg)
	}
	req := &report.Request{
		InBlob:     in.Nonce,
		GetAuxBlob: true,
	}

	resp, err := report.Get(m.client, req)
	if err != nil {
		errMsg := fmt.Errorf("failed to get mock TSM report: %v", err)
		return getEvidenceError(errMsg)
	}

	out := &tokens.TSMReport{
		Provider: resp.Provider,
		OutBlob:  resp.OutBlob,
		AuxBlob:  resp.AuxBlob,
	}

	outEncoded, err := out.ToJSON()
	if err != nil {
		errMsg := fmt.Errorf("failed to JSON encode mock TSM report: %v", err)
		return getEvidenceError(errMsg)
	}

	return &compositor.EvidenceOut{
		Status:   statusSucceeded,
		Evidence: outEncoded,
	}
}

func GetPlugin() *MockPlugin {
	return &MockPlugin{
		client: &faketsm.Client{
			Subsystems: map[string]configfsi.Client{
				"report": faketsm.ReportV7(0),
			},
		},
	}
}
