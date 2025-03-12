// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package mocktsm

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/veraison/ratsd/proto/compositor"
	"github.com/veraison/ratsd/tokens"
)

const (
	validNonceStr = "abcdefghijklmnopqrstuvwxyz123456abcdefghijklmnopqrstuvwxyz123456"
)

var (
	p = GetPlugin()
)

func Test_GetSubAttesterID(t *testing.T) {
	expected := &compositor.SubAttesterIDOut{
		SubAttesterID: sid,
		Status:        statusSucceeded,
	}

	assert.Equal(t, expected, p.GetSubAttesterID())
}

func Test_GetSupportedFormats(t *testing.T) {
	expected := &compositor.SupportedFormatsOut{
		Status:  statusSucceeded,
		Formats: supportedFormats,
	}

	assert.Equal(t, expected, p.GetSupportedFormats())
}

func Test_GetEvidence_wrong_nonce_size(t *testing.T) {
	inblob := []byte("abcdefghijklmnopqrstuvwxyz123456")
	in := &compositor.EvidenceIn{
		ContentType: string("mediaType"),
		Nonce:       inblob,
	}

	errMsg := fmt.Sprintf(
		"nonce size of the mockTSM attester should be %d, got %d", nonceSize, len(inblob))
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
			Error:  "no supported format in mock TSM plugin matches the requested format",
		},
	}

	assert.Equal(t, expected, p.GetEvidence(in))
}

func Test_GetEvidence_No_Options(t *testing.T) {
	inblob := []byte(validNonceStr)
	in := &compositor.EvidenceIn{
		ContentType: string(mediaType),
		Nonce:       inblob,
	}

	expectedOutblob := fmt.Sprintf("privlevel: 0\ninblob: %s", hex.EncodeToString(inblob))
	out := &tokens.TSMReport{
		Provider: "fake\n",
		OutBlob:  []byte(expectedOutblob),
		AuxBlob:  []byte("auxblob"),
	}

	outEncoded, _ := out.ToJSON()

	expected := &compositor.EvidenceOut{
		Status:   statusSucceeded,
		Evidence: outEncoded,
	}

	assert.Equal(t, expected, p.GetEvidence(in))
}

func TestGetEvidence_With_Invalid_Options(t *testing.T) {
	tests := []struct{name, params, msg string} {
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
				ContentType: string(mediaType),
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

func Test_GetEvidence_With_Valid_Privilege_level(t *testing.T) {
	inblob := []byte(validNonceStr)
	in := &compositor.EvidenceIn{
		ContentType: string(mediaType),
		Nonce:       inblob,
		Options:     []byte(`{"privilege_level": "1"}`),
	}

	expectedOutblob := fmt.Sprintf("privlevel: 1\ninblob: %s", hex.EncodeToString(inblob))
	out := &tokens.TSMReport {
		Provider: "fake\n",
		OutBlob:  []byte(expectedOutblob),
		AuxBlob:  []byte("auxblob"),
	}

	outEncoded, _ := out.ToJSON()

	expected := &compositor.EvidenceOut{
		Status:   statusSucceeded,
		Evidence: outEncoded,
	}

	assert.Equal(t, expected, p.GetEvidence(in))
}
