// Copyright 2025-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package tsm

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/google/go-configfs-tsm/configfs/configfsi"
	"github.com/google/go-configfs-tsm/configfs/linuxtsm"
	"github.com/google/go-configfs-tsm/report"
	"github.com/veraison/ratsd/proto/compositor"
	"github.com/veraison/ratsd/tokens"
)

const (
	tsmNonceSize = 64
)

var (
	sid = &compositor.SubAttesterID{
		Name:    "tsm-report",
		Version: "1.0.0",
	}

	supportedFormats = []*compositor.Format{
		&compositor.Format{
			ContentType: tokens.TSMReportMediaTypeJSON,
			NonceSize:   tsmNonceSize,
		},
		&compositor.Format{
			ContentType: tokens.TSMReportMediaTypeCBOR,
			NonceSize:   tsmNonceSize,
		},
	}

	supportedServiceProviders = []string{"svsm"}

	statusSucceeded = &compositor.Status{Result: true, Error: ""}
)

type TSMPlugin struct {
	newClient func() (configfsi.Client, error)
}

func (t *TSMPlugin) makeClient() (configfsi.Client, error) {
	if t.newClient != nil {
		return t.newClient()
	}
	return linuxtsm.MakeClient()
}

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
		&compositor.Option{Name: "service_provider", Type: "string"},
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
	if _, err := t.makeClient(); err != nil {
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
				GetAuxBlob: false,
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

			serviceProvider, hasServiceProvider := options["service_provider"]
			if hasServiceProvider && !slices.Contains(supportedServiceProviders, serviceProvider) {
				errMsg := fmt.Errorf("service_provider %q is invalid: expected one of %s",
					serviceProvider, strings.Join(supportedServiceProviders, ", "))
				return getEvidenceError(errMsg, http.StatusBadRequest)
			}

			client, err := t.makeClient()
			if err != nil {
				errMsg := fmt.Errorf("failed to create config TSM client: %v", err)
				return getEvidenceError(errMsg, http.StatusInternalServerError)
			}

			out, err := getReport(client, req, serviceProvider)
			if err != nil {
				errMsg := fmt.Errorf("failed to get TSM report: %v", err)
				return getEvidenceError(errMsg, http.StatusInternalServerError)
			}

			var encodeOp func() ([]byte, error)
			encodeAs := "JSON"

			if in.ContentType == tokens.TSMReportMediaTypeCBOR {
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
				Status:     statusSucceeded,
				Evidence:   outEncoded,
				StatusCode: http.StatusOK,
			}
		}
	}

	errMsg := fmt.Errorf("no supported format in tsm plugin matches the requested format")
	return getEvidenceError(errMsg, http.StatusBadRequest)
}

func getReport(client configfsi.Client, req *report.Request, serviceProvider string) (out *tokens.TSMReport, err error) {
	openReport, err := report.Create(client, req)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, openReport.Destroy())
	}()

	if serviceProvider != "" {
		if err := openReport.WriteOption("service_provider", []byte(serviceProvider)); err != nil {
			return nil, err
		}
	}

	resp, err := openReport.Get()
	if err != nil {
		return nil, err
	}
	out = &tokens.TSMReport{
		Provider: resp.Provider,
		OutBlob:  resp.OutBlob,
		AuxBlob:  resp.AuxBlob,
	}

	if strings.TrimSpace(resp.Provider) == "sev_guest" {
		out.AuxBlob, err = openReport.ReadOption("auxblob")
		if err != nil {
			return nil, err
		}
	}

	if serviceProvider == "svsm" {
		out.ServiceProvider = &serviceProvider
		out.ManifestBlob, err = openReport.ReadOption("manifestblob")
		if err != nil {
			return nil, err
		}
	}

	return out, nil
}
