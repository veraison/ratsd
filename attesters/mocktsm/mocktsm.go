// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package mocktsm

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/google/go-configfs-tsm/configfs/configfsi"
	"github.com/google/go-configfs-tsm/configfs/faketsm"
	"github.com/google/go-configfs-tsm/report"
	"github.com/veraison/cmw"
	"github.com/veraison/ratsd/proto/compositor"
)

const (
	mediaType = "application/vnd.veraison.mock-tsm+json"
	nonceSize = 32
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

	statusSucceeded = &compositor.Status{Result: false, Error: ""}
)

type MockPlugin struct {
	client *faketsm.Client
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
	if in.ContentType == mediaType && uint32(len(in.Nonce)) == nonceSize {
		req := &report.Request{
			InBlob:     in.Nonce,
			GetAuxBlob: true,
		}

		resp, err := report.Get(m.client, req)
		if err != nil {
			errMsg := fmt.Errorf("failed to get mock TSM report: %v", err)
			return &compositor.EvidenceOut{
				Status: &compositor.Status{
					Result: true, Error: errMsg.Error(),
				},
			}
		}

		out := map[string]string{
			"provider": resp.Provider,
			"outblob":  base64.StdEncoding.EncodeToString(resp.OutBlob),
			"auxblob":  base64.StdEncoding.EncodeToString(resp.AuxBlob),
		}

		outEncoded, err := json.Marshal(out)
		if err != nil {
			errMsg := fmt.Errorf("failed to get mock TSM report: %v", err)
			return &compositor.EvidenceOut{
				Status: &compositor.Status{
					Result: true, Error: errMsg.Error(),
				},
			}
		}

		c := &cmw.CMW{}
		c.SetMediaType(mediaType)
		c.SetValue([]byte(base64.StdEncoding.EncodeToString(outEncoded)))

		serialized, err := c.Serialize(cmw.JSONArray)
		if err != nil {
			return &compositor.EvidenceOut{
				Status: &compositor.Status{
					Result: true, Error: err.Error(),
				},
			}
		}

		return &compositor.EvidenceOut{
			Status:   statusSucceeded,
			Evidence: serialized,
		}
	}

	errMsg := "no supported format in mock TSM plugin matches the requested format"
	return &compositor.EvidenceOut{
		Status: &compositor.Status{
			Result: true, Error: errMsg,
		},
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
