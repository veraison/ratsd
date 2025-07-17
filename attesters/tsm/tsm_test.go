// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package tsm

import (
	"fmt"
	"testing"

	"github.com/google/go-configfs-tsm/configfs/linuxtsm"
	"github.com/stretchr/testify/assert"
	"github.com/veraison/ratsd/proto/compositor"
)

const (
	validNonceStr = "abcdefghijklmnopqrstuvwxyz123456abcdefghijklmnopqrstuvwxyz123456"
)

var (
	p = &TSMPlugin{}
)

func Test_getEvidenceError(t *testing.T) {
	e := fmt.Errorf("sample error")

	expected := &compositor.EvidenceOut{
		Status: &compositor.Status{
			Result: false, Error: "sample error",
		},
	}

	assert.Equal(t, expected, getEvidenceError(e))
}

func Test_GetOptions(t *testing.T) {
	options := []*compositor.Option{
		&compositor.Option{Name: "privilege_level", Type: "string"},
	}

	expected := &compositor.OptionsOut{
		Options: options,
		Status:  statusSucceeded,
	}

	assert.Equal(t, expected, p.GetOptions())
}

func Test_GetSubAttesterID(t *testing.T) {
	expected := &compositor.SubAttesterIDOut{
		SubAttesterID: sid,
		Status:        statusSucceeded,
	}

	assert.Equal(t, expected, p.GetSubAttesterID())
}

func Test_GetSupportedFormats(t *testing.T) {
	var expected *compositor.SupportedFormatsOut

	if _, err := linuxtsm.MakeClient(); err != nil {
		expected = &compositor.SupportedFormatsOut{
			Status: &compositor.Status{
				Result: false,
				Error:  fmt.Sprintf("TSM is not available: %s", err.Error()),
			},
		}
	} else {
		expected = &compositor.SupportedFormatsOut{
			Status:  statusSucceeded,
			Formats: supportedFormats,
		}
	}

	assert.Equal(t, expected, p.GetSupportedFormats())
}

func Test_GetEvidence_wrong_nonce_size(t *testing.T) {
	inblob := []byte("abcdefghijklmnopqrstuvwxyz123456")
	in := &compositor.EvidenceIn{
		ContentType: ApplicationvndVeraisonConfigfsTsmJson,
		Nonce:       inblob,
	}

	errMsg := fmt.Sprintf(
		"nonce size of the TSM attester should be %d, got %d", tsmNonceSize, len(inblob))
	expected := &compositor.EvidenceOut{
		Status: &compositor.Status{
			Result: false,
			Error:  errMsg,
		},
	}

	assert.Equal(t, expected, p.GetEvidence(in))
}

func Test_GetEvidence_invalid_format(t *testing.T) {
	inblob := []byte(validNonceStr)
	in := &compositor.EvidenceIn{
		ContentType: string("mediaType"),
		Nonce:       inblob,
	}

	expected := &compositor.EvidenceOut{
		Status: &compositor.Status{
			Result: false,
			Error:  "no supported format in tsm plugin matches the requested format",
		},
	}

	assert.Equal(t, expected, p.GetEvidence(in))
}

func TestGetEvidence_With_Invalid_Options(t *testing.T) {
	tests := []struct{ name, params, msg string }{
		{"privilege level not integer", `{"privilege_level": "invalid"}`,
			"privilege_level invalid is invalid"},
		{"privilege level less than zero", `{"privilege_level": "-20"}`,
			"privilege_level -20 is invalid"},
		{"invalid json", `{"privilege_level"}`,
			`failed to parse {"privilege_level"}: invalid character '}' after object key`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inblob := []byte(validNonceStr)
			in := &compositor.EvidenceIn{
				ContentType: ApplicationvndVeraisonConfigfsTsmJson,
				Nonce:       inblob,
				Options:     []byte(tt.params),
			}

			expected := &compositor.EvidenceOut{
				Status: &compositor.Status{
					Result: false,
					Error:  tt.msg,
				},
			}

			assert.Equal(t, expected, p.GetEvidence(in))
		})
	}
}
