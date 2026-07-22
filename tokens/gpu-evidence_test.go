// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package tokens

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/stretchr/testify/assert"
)

var (
	gpuNonce       = []byte("12345678901234567890123456789012")
	gpuReport      = []byte{0xaa, 0xbb, 0xcc, 0xdd}
	gpuCertificate = base64.StdEncoding.EncodeToString([]byte("certificate-chain"))
)

func validGPUEvidence() *GPUEvidence {
	return &GPUEvidence{
		Devices: []GPUDeviceEvidence{
			{
				Nonce:             gpuNonce,
				Arch:              "HOPPER",
				AttestationReport: gpuReport,
				CertificateChain:  gpuCertificate,
			},
		},
	}
}

func Test_GPUEvidence_MediaTypes(t *testing.T) {
	assert.Equal(t, "application/vnd.veraison.nvidia-gpu-evidence+json", GPUEvidenceMediaTypeJSON)
}

func Test_GPUEvidence_Valid_Pass(t *testing.T) {
	assert.NoError(t, validGPUEvidence().Valid())
}

func Test_GPUEvidence_Valid_Fail_MissingNonce(t *testing.T) {
	evidence := validGPUEvidence()
	evidence.Devices[0].Nonce = nil

	assert.EqualError(t, evidence.Valid(), `missing mandatory field "[0].nonce"`)
}

func Test_GPUEvidence_Valid_Fail_WrongNonceSize(t *testing.T) {
	evidence := validGPUEvidence()
	evidence.Devices[0].Nonce = []byte("short")

	assert.EqualError(t, evidence.Valid(), fmt.Sprintf(`invalid field "[0].nonce": expected %d bytes, got 5`, nvml.CC_GPU_CEC_NONCE_SIZE))
}

func Test_GPUEvidence_Valid_Fail_MissingDevices(t *testing.T) {
	evidence := validGPUEvidence()
	evidence.Devices = nil

	assert.EqualError(t, evidence.Valid(), "missing mandatory GPU evidence device")
}

func Test_GPUEvidence_FromJSON_Fail_NilEvidence(t *testing.T) {
	var evidence *GPUEvidence

	assert.EqualError(t, evidence.FromJSON([]byte("[]")), "JSON decoding failed: nil GPU evidence")
}

func Test_GPUEvidence_Valid_Fail_InvalidArch(t *testing.T) {
	evidence := validGPUEvidence()
	evidence.Devices[0].Arch = "AMPERE"

	assert.EqualError(t, evidence.Valid(), `invalid field "[0].arch": expected "BLACKWELL" or "HOPPER", got "AMPERE"`)
}

func Test_GPUEvidence_Valid_Fail_MissingCertificateChain(t *testing.T) {
	evidence := validGPUEvidence()
	evidence.Devices[0].CertificateChain = ""

	assert.EqualError(t, evidence.Valid(), `missing mandatory field "[0].certificate"`)
}

func Test_GPUEvidence_Valid_Fail_InvalidCertificateChain(t *testing.T) {
	evidence := validGPUEvidence()
	evidence.Devices[0].CertificateChain = "%"

	assert.ErrorContains(t, evidence.Valid(), `invalid field "[0].certificate"`)
}

func Test_GPUEvidence_JSON_WireShape(t *testing.T) {
	evidence := validGPUEvidence()

	encodedJSON, err := evidence.ToJSON()
	assert.NoError(t, err)

	var wire []map[string]string
	assert.NoError(t, json.Unmarshal(encodedJSON, &wire))
	assert.Equal(t, []map[string]string{
		{
			"arch":        "HOPPER",
			"certificate": gpuCertificate,
			"evidence":    base64.StdEncoding.EncodeToString(gpuReport),
			"nonce":       base64.StdEncoding.EncodeToString(gpuNonce),
		},
	}, wire)
}

func Test_GPUEvidence_JSON_SerDes_Pass(t *testing.T) {
	evidence := validGPUEvidence()

	encodedJSON, err := evidence.ToJSON()
	assert.NoError(t, err)

	decodedEvidence := &GPUEvidence{}
	assert.NoError(t, decodedEvidence.FromJSON(encodedJSON))

	assert.True(t, reflect.DeepEqual(evidence, decodedEvidence))
}
