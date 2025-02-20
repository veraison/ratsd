// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-configfs-tsm/configfs/linuxtsm"
	"github.com/google/go-configfs-tsm/report"
	"github.com/veraison/cmw"
	"github.com/veraison/ratsd/api"
	"github.com/veraison/ratsd/plugin"
	"github.com/veraison/ratsd/proto/compositor"
)

const (
	ApplicationvndVeraisonConfigfsTsmCbor = "application/vnd.veraison.configfs-tsm+cbor"
)

var (
	sid = &compositor.SubAttesterID{
		Name:    "tsm-report",
		Version: "1.0.0",
	}

	supportedFormats = []*compositor.Format{
		&compositor.Format{
			ContentType: string(api.ApplicationvndVeraisonConfigfsTsmJson),
			NonceSize:   32,
		},
		&compositor.Format{
			ContentType: ApplicationvndVeraisonConfigfsTsmCbor,
			NonceSize:   32,
		},
	}

	statusSucceeded = &compositor.Status{Result: false, Error: ""}
)

type TSMPlugin struct{}

func getEvidenceError(e error) *compositor.EvidenceOut {
	return &compositor.EvidenceOut{
		Status: &compositor.Status{
			Result: true, Error: e.Error(),
		},
	}
}

func (t *TSMPlugin) GetSubAttesterID() *compositor.SubAttesterIDOut {
	return &compositor.SubAttesterIDOut{
		SubAttesterID: sid,
		Status:        statusSucceeded,
	}
}

func (t *TSMPlugin) GetSupportedFormats() *compositor.SupportedFormatsOut {
	if _, err := linuxtsm.MakeClient(); err != nil {
		return &compositor.SupportedFormatsOut{
			Status: &compositor.Status{
				Result: true,
				Error:  fmt.Sprintf("TSM is not available:%s", err.Error()),
			},
		}
	}

	return &compositor.SupportedFormatsOut{
		Status:  statusSucceeded,
		Formats: supportedFormats,
	}
}

func (t *TSMPlugin) GetEvidence(in *compositor.EvidenceIn) *compositor.EvidenceOut {
	for _, format := range supportedFormats {
		if in.ContentType == format.ContentType && uint32(len(in.Nonce)) == format.NonceSize {
			client, err := linuxtsm.MakeClient()
			if err != nil {
				errMsg := fmt.Errorf("failed to create config TSM client: %v", err)
				return getEvidenceError(errMsg)
			}

			req := &report.Request{
				InBlob:     in.Nonce,
				GetAuxBlob: true,
			}

			resp, err := report.Get(client, req)
			if err != nil {
				errMsg := fmt.Errorf("failed to get TSM report: %v", err)
				return getEvidenceError(errMsg)
			}

			out := map[string]string{
				"provider": resp.Provider,
				"outblob":  base64.StdEncoding.EncodeToString(resp.OutBlob),
				"auxblob":  base64.StdEncoding.EncodeToString(resp.AuxBlob),
			}

			var encodeOp func(v any) ([]byte, error)
			if in.ContentType == ApplicationvndVeraisonConfigfsTsmCbor {
				encodeOp = cbor.Marshal
			} else {
				encodeOp = json.Marshal
			}

			outEncoded, err := encodeOp(out)
			if err != nil {
				return getEvidenceError(err)
			}
			c := &cmw.CMW{}
			c.SetMediaType(in.ContentType)
			c.SetValue([]byte(base64.StdEncoding.EncodeToString(outEncoded)))

			serialized, err := c.Serialize(cmw.JSONArray)
			if err != nil {
				return getEvidenceError(err)
			}

			return &compositor.EvidenceOut{
				Status:   statusSucceeded,
				Evidence: serialized,
			}
		}
	}

	errMsg := fmt.Errorf("no supported format in tsm plugin matches the requested format")
	return getEvidenceError(errMsg)
}

func main() {
	plugin.RegisterImplementation(&TSMPlugin{})
	plugin.Serve()
}
