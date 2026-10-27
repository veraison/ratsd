// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package tsm

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/google/go-configfs-tsm/configfs/configfsi"
	"github.com/google/go-configfs-tsm/configfs/faketsm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/ratsd-token/tokens"
	"github.com/veraison/ratsd/proto/compositor"
)

func fakeReportClient(provider string, privilegeFloor uint) *faketsm.ReportSubsystem {
	client := faketsm.ReportV7(privilegeFloor)
	makeEntry := client.MakeEntry
	client.MakeEntry = func() *faketsm.ReportEntry {
		entry := makeEntry()
		entry.InAttrs["service_provider"] = &faketsm.ReportAttributeState{}
		entry.InAttrs["service_guid"] = &faketsm.ReportAttributeState{}
		return entry
	}
	checkInAttr := client.CheckInAttr
	client.CheckInAttr = func(entry *faketsm.ReportEntry, attribute string, contents []byte) error {
		if attribute == "service_provider" && string(contents) == "svsm" {
			return nil
		}
		if attribute == "service_guid" && string(entry.InAttrs["service_provider"].Value) == "svsm" {
			return nil
		}
		return checkInAttr(entry, attribute, contents)
	}
	readAttr := client.ReadAttr
	client.ReadAttr = func(entry *faketsm.ReportEntry, attribute string) ([]byte, error) {
		switch attribute {
		case "provider":
			return []byte(provider), nil
		case "auxblob":
			if strings.TrimSpace(provider) != "sev_guest" {
				return nil, os.ErrNotExist
			}
		case "manifestblob":
			if string(entry.InAttrs["service_provider"].Value) != "svsm" {
				return nil, os.ErrNotExist
			}
			return []byte{0x00, 0xff, 0x01, 0x80}, nil
		}
		return readAttr(entry, attribute)
	}
	return client
}

func Test_GetEvidence_ServiceProvider(t *testing.T) {
	tests := []struct {
		name            string
		provider        string
		options         string
		serviceProvider string
		serviceGUID     string
		privilegeLevel  string
		privilegeFloor  uint
	}{
		{name: "default SEV-SNP", provider: "sev_guest\n", privilegeLevel: "0\n"},
		{name: "SEV-SNP with privilege level", provider: "sev_guest\n", options: `{"privilege_level":"1"}`, privilegeLevel: "1", privilegeFloor: 1},
		{name: "default TDX", provider: "tdx_guest\n", privilegeLevel: "0\n"},
		{name: "SVSM", provider: "sev_guest\n", options: `{"service_provider":"svsm"}`, serviceProvider: "svsm", privilegeLevel: "0\n"},
		{name: "SVSM with guest privilege floor 1", provider: "sev_guest\n", options: `{"service_provider":"svsm"}`, serviceProvider: "svsm", privilegeLevel: "0\n", privilegeFloor: 1},
		{name: "SVSM with privilege level", provider: "sev_guest\n", options: `{"service_provider":"svsm","privilege_level":"1"}`, serviceProvider: "svsm", privilegeLevel: "1"},
		{
			name: "SVSM with vTPM GUID", provider: "sev_guest\n", serviceProvider: "svsm", privilegeLevel: "0\n",
			options:     `{"service_provider":"svsm","service_guid":"c476f1eb-0123-45a5-9641-b4e7dde5bfe3"}`,
			serviceGUID: "c476f1eb-0123-45a5-9641-b4e7dde5bfe3",
		},
		{
			name: "SVSM with another GUID", provider: "sev_guest\n", serviceProvider: "svsm", privilegeLevel: "0\n",
			options:     `{"service_provider":"svsm","service_guid":"11111111-2222-3333-4444-555555555555"}`,
			serviceGUID: "11111111-2222-3333-4444-555555555555",
		},
		{
			name: "SVSM with null GUID", provider: "sev_guest\n", serviceProvider: "svsm", privilegeLevel: "0\n",
			options:     `{"service_provider":"svsm","service_guid":"00000000-0000-0000-0000-000000000000"}`,
			serviceGUID: "00000000-0000-0000-0000-000000000000",
		},
	}

	for _, test := range tests {
		for _, contentType := range []string{tokens.TSMReportMediaTypeJSON, tokens.TSMReportMediaTypeCBOR} {
			t.Run(test.name+"/"+contentType, func(t *testing.T) {
				client := fakeReportClient(test.provider, test.privilegeFloor)
				writes := make(map[string]int)
				checkInAttr := client.CheckInAttr
				client.CheckInAttr = func(entry *faketsm.ReportEntry, attribute string, contents []byte) error {
					writes[attribute]++
					return checkInAttr(entry, attribute, contents)
				}
				created := 0
				makeEntry := client.MakeEntry
				client.MakeEntry = func() *faketsm.ReportEntry {
					created++
					return makeEntry()
				}
				reads := make(map[string]int)
				readAttr := client.ReadAttr
				client.ReadAttr = func(entry *faketsm.ReportEntry, attribute string) ([]byte, error) {
					reads[attribute]++
					assert.Equal(t, validNonceStr, string(entry.InAttrs["inblob"].Value))
					assert.Equal(t, test.privilegeLevel, string(entry.InAttrs["privlevel"].Value))
					assert.Equal(t, test.serviceProvider, string(entry.InAttrs["service_provider"].Value))
					assert.Equal(t, test.serviceGUID, string(entry.InAttrs["service_guid"].Value))
					return readAttr(entry, attribute)
				}
				plugin := &TSMPlugin{newClient: func() (configfsi.Client, error) { return client, nil }}
				result := plugin.GetEvidence(&compositor.EvidenceIn{
					ContentType: contentType,
					Nonce:       []byte(validNonceStr),
					Options:     []byte(test.options),
				})

				assert.Equal(t, 1, created)
				assert.Empty(t, client.Entries)
				require.True(t, result.Status.Result, result.Status.Error)
				require.EqualValues(t, http.StatusOK, result.StatusCode)
				if test.serviceGUID != "" {
					assert.Equal(t, 1, writes["service_guid"])
				} else {
					assert.Zero(t, writes["service_guid"])
				}
				decoded := &tokens.TSMReport{}
				if contentType == tokens.TSMReportMediaTypeJSON {
					require.NoError(t, decoded.FromJSON(result.Evidence))
				} else {
					require.NoError(t, decoded.FromCBOR(result.Evidence))
				}
				assert.Equal(t, test.provider, decoded.Provider)
				assert.Contains(t, string(decoded.OutBlob), "inblob: ")
				assert.Equal(t, 1, reads["outblob"])
				if test.provider == "sev_guest\n" {
					assert.Equal(t, tokens.BinaryString("auxblob"), decoded.AuxBlob)
					assert.Equal(t, 1, reads["auxblob"])
				} else {
					assert.Empty(t, decoded.AuxBlob)
					assert.Zero(t, reads["auxblob"])
				}
				if test.serviceProvider == "svsm" {
					require.NotNil(t, decoded.ServiceProvider)
					assert.Equal(t, "svsm", *decoded.ServiceProvider)
					assert.Equal(t, tokens.BinaryString{0x00, 0xff, 0x01, 0x80}, decoded.ManifestBlob)
					assert.Equal(t, 1, reads["manifestblob"])
				} else {
					assert.Nil(t, decoded.ServiceProvider)
					assert.Empty(t, decoded.ManifestBlob)
					assert.Zero(t, reads["manifestblob"])
				}
			})
		}
	}
}

func Test_GetEvidence_SVSM_Failure(t *testing.T) {
	tests := []struct {
		name      string
		attribute string
		tamper    bool
		options   string
	}{
		{name: "service provider unavailable", attribute: "service_provider"},
		{
			name: "service GUID write failure", attribute: "service_guid",
			options: `{"service_provider":"svsm","service_guid":"c476f1eb-0123-45a5-9641-b4e7dde5bfe3"}`,
		},
		{
			name: "invalid service GUID delegated to configfs", attribute: "service_guid",
			options: `{"service_provider":"svsm","service_guid":"invalid"}`,
		},
		{
			name: "empty service GUID delegated to configfs", attribute: "service_guid",
			options: `{"service_provider":"svsm","service_guid":""}`,
		},
		{name: "report read failure", attribute: "outblob"},
		{name: "certificate read failure", attribute: "auxblob"},
		{name: "manifest read failure", attribute: "manifestblob"},
		{name: "manifest generation mismatch", attribute: "manifestblob", tamper: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := fakeReportClient("sev_guest\n", 0)
			checkInAttr := client.CheckInAttr
			client.CheckInAttr = func(entry *faketsm.ReportEntry, attribute string, contents []byte) error {
				if attribute == test.attribute {
					return errors.New("unavailable")
				}
				return checkInAttr(entry, attribute, contents)
			}
			readAttr := client.ReadAttr
			client.ReadAttr = func(entry *faketsm.ReportEntry, attribute string) ([]byte, error) {
				if attribute == test.attribute {
					if test.tamper {
						entry.WriteGeneration++
					} else {
						return nil, errors.New("unavailable")
					}
				}
				return readAttr(entry, attribute)
			}
			plugin := &TSMPlugin{newClient: func() (configfsi.Client, error) { return client, nil }}
			options := test.options
			if options == "" {
				options = `{"service_provider":"svsm"}`
			}
			result := plugin.GetEvidence(&compositor.EvidenceIn{
				ContentType: tokens.TSMReportMediaTypeJSON,
				Nonce:       []byte(validNonceStr),
				Options:     []byte(options),
			})

			assert.False(t, result.Status.Result)
			assert.EqualValues(t, http.StatusInternalServerError, result.StatusCode)
			assert.Contains(t, result.Status.Error, test.attribute)
			if test.tamper {
				assert.Contains(t, result.Status.Error, "report generation was")
			} else {
				assert.Contains(t, result.Status.Error, "unavailable")
			}
			assert.Empty(t, result.Evidence)
			assert.Empty(t, client.Entries)
		})
	}
}
