// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package gpu

import (
	"errors"
	"fmt"
	"testing"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/certs"
	nvgpu "github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/gpu"
	nvmocks "github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/veraison/ratsd/proto/compositor"
	"github.com/veraison/ratsd/tokens"
)

type fakeCollector struct {
	devices         []nvgpu.GPUDevice
	collectErr      error
	shutdownErr     error
	collectedNonce  []byte
	shutdownInvoked bool
}

func (f *fakeCollector) CollectEvidence(nonce []byte) ([]nvgpu.GPUDevice, error) {
	f.collectedNonce = append([]byte(nil), nonce...)
	if f.collectErr != nil {
		return nil, f.collectErr
	}

	return f.devices, nil
}

func (f *fakeCollector) Shutdown() error {
	f.shutdownInvoked = true
	return f.shutdownErr
}

func makePlugin(factory collectorFactory) *GPUPlugin {
	return &GPUPlugin{newCollector: factory}
}

func validGPUDevices(t *testing.T) []nvgpu.GPUDevice {
	t.Helper()

	certChain := certs.NewCertChainFromData(nvmocks.ValidCertChainData)
	requireErr := certChain.Verify()
	assert.NoError(t, requireErr)

	return []nvgpu.GPUDevice{
		nvgpu.NewGPUDevice(
			nvml.DEVICE_ARCH_HOPPER,
			[]byte("attestation-report"),
			certChain,
		),
	}
}

func Test_GetOptions(t *testing.T) {
	expected := &compositor.OptionsOut{
		Options: []*compositor.Option{},
		Status:  statusSucceeded,
	}

	assert.Equal(t, expected, NewPlugin().GetOptions())
}

func Test_GetSubAttesterID(t *testing.T) {
	expected := &compositor.SubAttesterIDOut{
		SubAttesterID: sid,
		Status:        statusSucceeded,
	}

	assert.Equal(t, expected, NewPlugin().GetSubAttesterID())
}

func Test_GetSupportedFormats(t *testing.T) {
	collector := &fakeCollector{}
	p := makePlugin(func() (evidenceCollector, error) {
		return collector, nil
	})

	expected := &compositor.SupportedFormatsOut{
		Status:  statusSucceeded,
		Formats: supportedFormats,
	}

	assert.Equal(t, expected, p.GetSupportedFormats())
	assert.True(t, collector.shutdownInvoked)
}

func Test_GetSupportedFormats_InitFailure(t *testing.T) {
	p := makePlugin(func() (evidenceCollector, error) {
		return nil, errors.New("nvml unavailable")
	})

	expected := &compositor.SupportedFormatsOut{
		Status: &compositor.Status{
			Result: false,
			Error:  "GPU evidence collection is not available: nvml unavailable",
		},
	}

	assert.Equal(t, expected, p.GetSupportedFormats())
}

func Test_GetEvidence_WrongNonceSize(t *testing.T) {
	in := &compositor.EvidenceIn{
		ContentType: ApplicationvndVeraisonNvGpuEvidenceJSON,
		Nonce:       []byte("short"),
	}

	errMsg := fmt.Sprintf(
		"nonce size of the GPU attester should be %d, got %d",
		gpuNonceSize, len(in.Nonce),
	)
	expected := &compositor.EvidenceOut{
		Status: &compositor.Status{
			Result: false,
			Error:  errMsg,
		},
	}

	assert.Equal(t, expected, NewPlugin().GetEvidence(in))
}

func Test_GetEvidence_InvalidFormat(t *testing.T) {
	in := &compositor.EvidenceIn{
		ContentType: "application/invalid",
		Nonce:       []byte("12345678901234567890123456789012"),
	}

	expected := &compositor.EvidenceOut{
		Status: &compositor.Status{
			Result: false,
			Error:  "no supported format in gpu plugin matches the requested format",
		},
	}

	assert.Equal(t, expected, NewPlugin().GetEvidence(in))
}

func Test_GetEvidence_InvalidOptions(t *testing.T) {
	tests := []struct {
		name string
		opts string
		msg  string
	}{
		{
			name: "invalid json",
			opts: `{"mode"}`,
			msg:  `failed to parse {"mode"}: invalid character '}' after object key`,
		},
		{
			name: "unsupported option",
			opts: `{"mode":"full"}`,
			msg:  "gpu attester does not support options",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := &compositor.EvidenceIn{
				ContentType: ApplicationvndVeraisonNvGpuEvidenceJSON,
				Nonce:       []byte("12345678901234567890123456789012"),
				Options:     []byte(tt.opts),
			}

			expected := &compositor.EvidenceOut{
				Status: &compositor.Status{
					Result: false,
					Error:  tt.msg,
				},
			}

			assert.Equal(t, expected, NewPlugin().GetEvidence(in))
		})
	}
}

func Test_GetEvidence_CollectFailure(t *testing.T) {
	collector := &fakeCollector{
		collectErr: errors.New("collection failed"),
	}
	p := makePlugin(func() (evidenceCollector, error) {
		return collector, nil
	})

	in := &compositor.EvidenceIn{
		ContentType: ApplicationvndVeraisonNvGpuEvidenceJSON,
		Nonce:       []byte("12345678901234567890123456789012"),
	}

	expected := &compositor.EvidenceOut{
		Status: &compositor.Status{
			Result: false,
			Error:  "failed to collect GPU evidence: collection failed",
		},
	}

	assert.Equal(t, expected, p.GetEvidence(in))
	assert.True(t, collector.shutdownInvoked)
}

func Test_GetEvidence_JSON(t *testing.T) {
	collector := &fakeCollector{
		devices: validGPUDevices(t),
	}
	p := makePlugin(func() (evidenceCollector, error) {
		return collector, nil
	})

	nonce := []byte("12345678901234567890123456789012")
	in := &compositor.EvidenceIn{
		ContentType: ApplicationvndVeraisonNvGpuEvidenceJSON,
		Nonce:       nonce,
	}

	expectedToken := &tokens.GPUEvidence{
		Nonce: nonce,
		Devices: []tokens.GPUDeviceEvidence{
			{
				Arch:              "HOPPER",
				AttestationReport: []byte("attestation-report"),
				CertificateChain:  mustCertChainBase64(t),
			},
		},
	}
	expectedEvidence, err := expectedToken.ToJSON()
	assert.NoError(t, err)

	expected := &compositor.EvidenceOut{
		Status:   statusSucceeded,
		Evidence: expectedEvidence,
	}

	assert.Equal(t, expected, p.GetEvidence(in))
	assert.Equal(t, nonce, collector.collectedNonce)
	assert.True(t, collector.shutdownInvoked)
}

func Test_GetEvidence_CBOR(t *testing.T) {
	collector := &fakeCollector{
		devices: validGPUDevices(t),
	}
	p := makePlugin(func() (evidenceCollector, error) {
		return collector, nil
	})

	nonce := []byte("12345678901234567890123456789012")
	in := &compositor.EvidenceIn{
		ContentType: ApplicationvndVeraisonNvGpuEvidenceCBOR,
		Nonce:       nonce,
	}

	expectedToken := &tokens.GPUEvidence{
		Nonce: nonce,
		Devices: []tokens.GPUDeviceEvidence{
			{
				Arch:              "HOPPER",
				AttestationReport: []byte("attestation-report"),
				CertificateChain:  mustCertChainBase64(t),
			},
		},
	}
	expectedEvidence, err := expectedToken.ToCBOR()
	assert.NoError(t, err)

	expected := &compositor.EvidenceOut{
		Status:   statusSucceeded,
		Evidence: expectedEvidence,
	}

	assert.Equal(t, expected, p.GetEvidence(in))
}

func Test_GetEvidence_ShutdownFailure(t *testing.T) {
	collector := &fakeCollector{
		devices:     validGPUDevices(t),
		shutdownErr: errors.New("shutdown failed"),
	}
	p := makePlugin(func() (evidenceCollector, error) {
		return collector, nil
	})

	in := &compositor.EvidenceIn{
		ContentType: ApplicationvndVeraisonNvGpuEvidenceJSON,
		Nonce:       []byte("12345678901234567890123456789012"),
	}

	expected := &compositor.EvidenceOut{
		Status: &compositor.Status{
			Result: false,
			Error:  "failed to shutdown GPU evidence collector: shutdown failed",
		},
	}

	assert.Equal(t, expected, p.GetEvidence(in))
}

func mustCertChainBase64(t *testing.T) string {
	t.Helper()

	certChain := certs.NewCertChainFromData(nvmocks.ValidCertChainData)
	encoded, err := certChain.EncodeBase64()
	assert.NoError(t, err)

	return encoded
}
