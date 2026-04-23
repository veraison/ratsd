// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package tokens

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	gpuNonce  = []byte("12345678901234567890123456789012")
	gpuReport = []byte{0xaa, 0xbb, 0xcc, 0xdd}
)

func validGPUEvidence() *GPUEvidence {
	return &GPUEvidence{
		Nonce: gpuNonce,
		Devices: []GPUDeviceEvidence{
			{
				Arch:              "HOPPER",
				AttestationReport: gpuReport,
				CertificateChain:  "certificate-chain",
			},
		},
	}
}

func Test_GPUEvidence_Valid_Pass(t *testing.T) {
	assert.NoError(t, validGPUEvidence().Valid())
}

func Test_GPUEvidence_Valid_Fail_MissingNonce(t *testing.T) {
	evidence := validGPUEvidence()
	evidence.Nonce = nil

	assert.EqualError(t, evidence.Valid(), `missing mandatory field "nonce"`)
}

func Test_GPUEvidence_Valid_Fail_MissingDevices(t *testing.T) {
	evidence := validGPUEvidence()
	evidence.Devices = nil

	assert.EqualError(t, evidence.Valid(), `missing mandatory field "devices"`)
}

func Test_GPUEvidence_Valid_Fail_MissingCertificateChain(t *testing.T) {
	evidence := validGPUEvidence()
	evidence.Devices[0].CertificateChain = ""

	assert.EqualError(t, evidence.Valid(), `missing mandatory field "devices[0].certificate_chain"`)
}

func Test_GPUEvidence_JSON_SerDes_Pass(t *testing.T) {
	evidence := validGPUEvidence()

	encodedJSON, err := evidence.ToJSON()
	assert.NoError(t, err)

	decodedEvidence := &GPUEvidence{}
	assert.NoError(t, decodedEvidence.FromJSON(encodedJSON))

	assert.True(t, reflect.DeepEqual(evidence, decodedEvidence))
}

func Test_GPUEvidence_CBOR_SerDes_Pass(t *testing.T) {
	evidence := validGPUEvidence()

	encodedCBOR, err := evidence.ToCBOR()
	assert.NoError(t, err)

	decodedEvidence := &GPUEvidence{}
	assert.NoError(t, decodedEvidence.FromCBOR(encodedCBOR))

	assert.True(t, reflect.DeepEqual(evidence, decodedEvidence))
}
