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
