// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package nvgpu

import (
	"errors"
	"fmt"
	"testing"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/certs"
	nvtrustgpu "github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/gpu"
	nvmocks "github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/veraison/ratsd/proto/compositor"
	"github.com/veraison/ratsd/tokens"
)

type fakeCollector struct {
	devices         []nvtrustgpu.GPUDevice
	collectErr      error
	shutdownErr     error
	collectedNonce  []byte
	shutdownInvoked bool
}

func (f *fakeCollector) CollectEvidence(nonce []byte) ([]nvtrustgpu.GPUDevice, error) {
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

func makePlugin(factory collectorFactory) *Plugin {
	return newPlugin(factory)
}

func availablePlugin() *Plugin {
	return makePlugin(func() (evidenceCollector, error) {
		return &fakeCollector{}, nil
	})
}

func validGPUDevices(t *testing.T) []nvtrustgpu.GPUDevice {
	t.Helper()

	certChain := certs.NewCertChainFromData(nvmocks.ValidCertChainData)
	requireErr := certChain.Verify()
	assert.NoError(t, requireErr)

	return []nvtrustgpu.GPUDevice{
		nvtrustgpu.NewGPUDevice(
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

	assert.Equal(t, expected, availablePlugin().GetOptions())
}

func Test_GetSubAttesterID(t *testing.T) {
	expected := &compositor.SubAttesterIDOut{
		SubAttesterID: sid,
		Status:        statusSucceeded,
	}

	assert.Equal(t, expected, availablePlugin().GetSubAttesterID())
}

func Test_GetSupportedFormats(t *testing.T) {
	collector := &fakeCollector{}
	factoryCalls := 0
	p := makePlugin(func() (evidenceCollector, error) {
		factoryCalls++
		return collector, nil
	})

	expected := &compositor.SupportedFormatsOut{
		Status:  statusSucceeded,
		Formats: supportedFormats,
	}

	assert.Equal(t, expected, p.GetSupportedFormats())
	assert.Equal(t, 1, factoryCalls)
	assert.True(t, collector.shutdownInvoked)
}

func Test_GetSupportedFormats_InitFailure(t *testing.T) {
	p := makePlugin(func() (evidenceCollector, error) {
		return nil, errors.New("nvml unavailable")
	})

	expected := &compositor.SupportedFormatsOut{
		Status: &compositor.Status{
			Result: false,
			Error:  "NVIDIA GPU evidence collection is not available: nvml unavailable",
		},
	}

	assert.Equal(t, expected, p.GetSupportedFormats())
}

func Test_GetSupportedFormats_ShutdownFailure(t *testing.T) {
	p := makePlugin(func() (evidenceCollector, error) {
		return &fakeCollector{shutdownErr: errors.New("shutdown failed")}, nil
	})

	expected := &compositor.SupportedFormatsOut{
		Status: &compositor.Status{
			Result: false,
			Error:  "NVIDIA GPU evidence collection is not available: shutdown failed",
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
		"nonce size of the NVIDIA GPU attester should be %d, got %d",
		nonceSize, len(in.Nonce),
	)
	expected := &compositor.EvidenceOut{
		Status: &compositor.Status{
			Result: false,
			Error:  errMsg,
		},
	}

	assert.Equal(t, expected, availablePlugin().GetEvidence(in))
}

func Test_GetEvidence_InvalidFormat(t *testing.T) {
	in := &compositor.EvidenceIn{
		ContentType: "application/invalid",
		Nonce:       []byte("12345678901234567890123456789012"),
	}

	expected := &compositor.EvidenceOut{
		Status: &compositor.Status{
			Result: false,
			Error:  "no supported format in nvgpu plugin matches the requested format",
		},
	}

	assert.Equal(t, expected, availablePlugin().GetEvidence(in))
}

func Test_GetEvidence_CBORMediaTypeUnsupported(t *testing.T) {
	in := &compositor.EvidenceIn{
		ContentType: "application/vnd.veraison.nvidia-gpu-evidence+cbor",
		Nonce:       []byte("12345678901234567890123456789012"),
	}

	expected := &compositor.EvidenceOut{
		Status: &compositor.Status{
			Result: false,
			Error:  "no supported format in nvgpu plugin matches the requested format",
		},
	}

	assert.Equal(t, expected, availablePlugin().GetEvidence(in))
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
			msg:  "NVIDIA GPU attester does not support options",
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

			assert.Equal(t, expected, availablePlugin().GetEvidence(in))
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
		Devices: []tokens.GPUDeviceEvidence{
			{
				Nonce:             nonce,
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
