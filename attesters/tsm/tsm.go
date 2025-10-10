// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package tsm

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/google/go-configfs-tsm/configfs/linuxtsm"
	"github.com/google/go-configfs-tsm/report"
	"github.com/veraison/ratsd/proto/compositor"
	"github.com/veraison/ratsd/tokens"
)

const (
	ApplicationvndVeraisonConfigfsTsmCbor = "application/vnd.veraison.configfs-tsm+cbor"
	ApplicationvndVeraisonConfigfsTsmJson = "application/vnd.veraison.configfs-tsm+json"
	tsmNonceSize                          = 64
)

var (
	sid = &compositor.SubAttesterID{
		Name:    "tsm-report",
		Version: "1.0.0",
	}

	supportedFormats = []*compositor.Format{
		&compositor.Format{
			ContentType: ApplicationvndVeraisonConfigfsTsmJson,
			NonceSize:   tsmNonceSize,
		},
		&compositor.Format{
			ContentType: ApplicationvndVeraisonConfigfsTsmCbor,
			NonceSize:   tsmNonceSize,
		},
	}

	statusSucceeded = &compositor.Status{Result: true, Error: ""}
)

type TSMPlugin struct{}

func getEvidenceError(e error, statusCode uint32) *compositor.EvidenceOut {
	return &compositor.EvidenceOut{
		Status: &compositor.Status{
			Result: false, Error: e.Error(),
		},
		StatusCode: statusCode,
	}
}

func (t *TSMPlugin) GetOptions() *compositor.OptionsOut {
	options := []*compositor.Option{
		&compositor.Option{Name: "privilege_level", Type: "string"},
	}

	return &compositor.OptionsOut{
		Options: options,
		Status:  statusSucceeded,
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
				Result: false,
				Error:  fmt.Sprintf("TSM is not available: %s", err.Error()),
			},
		}
	}

	return &compositor.SupportedFormatsOut{
		Status:  statusSucceeded,
		Formats: supportedFormats,
	}
}

func (t *TSMPlugin) GetEvidence(in *compositor.EvidenceIn) *compositor.EvidenceOut {
	if uint32(len(in.Nonce)) != tsmNonceSize {
		errMsg := fmt.Errorf(
			"nonce size of the TSM attester should be %d, got %d",
			tsmNonceSize, uint32(len(in.Nonce)))
		return getEvidenceError(errMsg, http.StatusBadRequest)
	}

	for _, format := range supportedFormats {
		if in.ContentType == format.ContentType {
			req := &report.Request{
				InBlob:     in.Nonce,
				GetAuxBlob: true,
			}

			options := make(map[string]string)
			if len(in.Options) > 0 {
				if err := json.Unmarshal(in.Options, &options); err != nil {
					errMsg := fmt.Errorf(
						"failed to parse %s: %v", in.Options, err)
					return getEvidenceError(errMsg, http.StatusBadRequest)
				}
			}

			if privlevel, ok := options["privilege_level"]; ok {
				level, err := strconv.Atoi(privlevel)
				if err != nil || level < 0 {
					errMsg := fmt.Errorf("privilege_level %s is invalid",
						privlevel)
					return getEvidenceError(errMsg, http.StatusBadRequest)
				}
				req.Privilege = &report.Privilege{Level: uint(level)}
			}

			client, err := linuxtsm.MakeClient()
			if err != nil {
				errMsg := fmt.Errorf("failed to create config TSM client: %v", err)
				return getEvidenceError(errMsg, http.StatusInternalServerError)
			}

			resp, err := report.Get(client, req)
			if err != nil {
				errMsg := fmt.Errorf("failed to get TSM report: %v", err)
				return getEvidenceError(errMsg, http.StatusInternalServerError)
			}

			out := &tokens.TSMReport{
				Provider: resp.Provider,
				OutBlob:  resp.OutBlob,
				AuxBlob:  resp.AuxBlob,
			}

			var encodeOp func() ([]byte, error)
			encodeAs := "JSON"

			if in.ContentType == ApplicationvndVeraisonConfigfsTsmCbor {
				encodeOp = out.ToCBOR
				encodeAs = "CBOR"
			} else {
				encodeOp = out.ToJSON
			}

			outEncoded, err := encodeOp()
			if err != nil {
				errMsg := fmt.Errorf("failed to encode TSM report as %s: %v", encodeAs, err)
				return getEvidenceError(errMsg, http.StatusInternalServerError)
			}

			return &compositor.EvidenceOut{
				Status:   statusSucceeded,
				Evidence: outEncoded,
				StatusCode: http.StatusOK,
			}
		}
	}

	errMsg := fmt.Errorf("no supported format in tsm plugin matches the requested format")
	return getEvidenceError(errMsg, http.StatusBadRequest)
}
