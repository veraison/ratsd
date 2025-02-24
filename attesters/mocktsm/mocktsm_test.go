// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package mocktsm

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/veraison/ratsd/proto/compositor"
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

func Test_GetEvidence(t *testing.T) {
	inblob := []byte(validNonceStr)
	in := &compositor.EvidenceIn{
		ContentType: string(mediaType),
		Nonce:       inblob,
	}

	expectedOutblob := fmt.Sprintf("privlevel: 0\ninblob: %s", hex.EncodeToString(inblob))
	out := map[string]string{
		"provider": "fake\n",
		"outblob":  base64.RawURLEncoding.EncodeToString([]byte(expectedOutblob)),
		"auxblob":  base64.RawURLEncoding.EncodeToString([]byte("auxblob")),
	}

	outEncoded, _ := json.Marshal(out)

	expected := &compositor.EvidenceOut{
		Status:   statusSucceeded,
		Evidence: outEncoded,
	}

	assert.Equal(t, expected, p.GetEvidence(in))
}
