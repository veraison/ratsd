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
	"github.com/veraison/cmw"
	"github.com/veraison/ratsd/proto/compositor"
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

func Test_GetEvidence_invalid_format(t *testing.T) {
	inblob := []byte("abcdefghijklmnopqrstuvwxyz123456")
	in := &compositor.EvidenceIn{
		ContentType: string("mediaType"),
		Nonce:       inblob,
	}

	expected := &compositor.EvidenceOut{
		Status: &compositor.Status{
			Result: true,
			Error:  "no supported format in mock TSM plugin matches the requested format",
		},
	}

	assert.Equal(t, expected, p.GetEvidence(in))
}

func Test_GetEvidence(t *testing.T) {
	inblob := []byte("abcdefghijklmnopqrstuvwxyz123456")
	in := &compositor.EvidenceIn{
		ContentType: string(mediaType),
		Nonce:       inblob,
	}

	expectedOutblob := fmt.Sprintf("privlevel: 0\ninblob: %s", hex.EncodeToString(inblob))
	out := map[string]string{
		"provider": "fake\n",
		"outblob":  base64.StdEncoding.EncodeToString([]byte(expectedOutblob)),
		"auxblob":  base64.StdEncoding.EncodeToString([]byte("auxblob")),
	}

	outEncoded, _ := json.Marshal(out)
	c := &cmw.CMW{}
	c.SetMediaType(mediaType)
	c.SetValue([]byte(base64.StdEncoding.EncodeToString(outEncoded)))

	serialized, _ := c.Serialize(cmw.JSONArray)
	expected := &compositor.EvidenceOut{
		Status:   statusSucceeded,
		Evidence: serialized,
	}

	assert.Equal(t, expected, p.GetEvidence(in))
}
