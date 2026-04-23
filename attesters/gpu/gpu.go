// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package gpu

import (
	"encoding/json"
	"fmt"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	nvgpu "github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/gpu"
	"github.com/veraison/ratsd/proto/compositor"
	"github.com/veraison/ratsd/tokens"
)

const (
	ApplicationvndVeraisonNvGpuEvidenceJSON = tokens.GPUEvidenceMediaTypeJSON
	ApplicationvndVeraisonNvGpuEvidenceCBOR = tokens.GPUEvidenceMediaTypeCBOR
	gpuNonceSize                            = nvml.CC_GPU_CEC_NONCE_SIZE
)

var (
	sid = &compositor.SubAttesterID{
		Name:    "nv-gpu-evidence",
		Version: "1.0.0",
	}

	supportedFormats = []*compositor.Format{
		{
			ContentType: ApplicationvndVeraisonNvGpuEvidenceJSON,
			NonceSize:   gpuNonceSize,
		},
		{
			ContentType: ApplicationvndVeraisonNvGpuEvidenceCBOR,
			NonceSize:   gpuNonceSize,
		},
	}

	statusSucceeded = &compositor.Status{Result: true, Error: ""}
)

type evidenceCollector interface {
	CollectEvidence(nonce []byte) ([]nvgpu.GPUDevice, error)
	Shutdown() error
}

type collectorFactory func() (evidenceCollector, error)

type GPUPlugin struct {
	newCollector collectorFactory
}

func NewPlugin() *GPUPlugin {
	return &GPUPlugin{newCollector: defaultCollectorFactory}
}

func defaultCollectorFactory() (evidenceCollector, error) {
	return nvgpu.NewNvmlGPUAdmin(nil)
}

func getEvidenceError(e error) *compositor.EvidenceOut {
	return &compositor.EvidenceOut{
		Status: &compositor.Status{
			Result: false,
			Error:  e.Error(),
		},
	}
}

func (g *GPUPlugin) GetOptions() *compositor.OptionsOut {
	return &compositor.OptionsOut{
		Options: []*compositor.Option{},
		Status:  statusSucceeded,
	}
}

func (g *GPUPlugin) GetSubAttesterID() *compositor.SubAttesterIDOut {
	return &compositor.SubAttesterIDOut{
		SubAttesterID: sid,
		Status:        statusSucceeded,
	}
}

func (g *GPUPlugin) GetSupportedFormats() *compositor.SupportedFormatsOut {
	collector, err := g.newCollector()
	if err != nil {
		return &compositor.SupportedFormatsOut{
			Status: &compositor.Status{
				Result: false,
				Error:  fmt.Sprintf("GPU evidence collection is not available: %s", err.Error()),
			},
		}
	}

	if err := collector.Shutdown(); err != nil {
		return &compositor.SupportedFormatsOut{
			Status: &compositor.Status{
				Result: false,
				Error:  fmt.Sprintf("GPU evidence collection is not available: %s", err.Error()),
			},
		}
	}

	return &compositor.SupportedFormatsOut{
		Status:  statusSucceeded,
		Formats: supportedFormats,
	}
}

func (g *GPUPlugin) GetEvidence(in *compositor.EvidenceIn) *compositor.EvidenceOut {
	if uint32(len(in.Nonce)) != gpuNonceSize {
		errMsg := fmt.Errorf(
			"nonce size of the GPU attester should be %d, got %d",
			gpuNonceSize, uint32(len(in.Nonce)),
		)
		return getEvidenceError(errMsg)
	}

	if err := validateOptions(in.Options); err != nil {
		return getEvidenceError(err)
	}

	if !supportsFormat(in.ContentType) {
		return getEvidenceError(fmt.Errorf("no supported format in gpu plugin matches the requested format"))
	}

	collector, err := g.newCollector()
	if err != nil {
		return getEvidenceError(fmt.Errorf("failed to initialize GPU evidence collector: %v", err))
	}

	devices, collectErr := collector.CollectEvidence(in.Nonce)
	shutdownErr := collector.Shutdown()

	if collectErr != nil {
		return getEvidenceError(fmt.Errorf("failed to collect GPU evidence: %v", collectErr))
	}
	if shutdownErr != nil {
		return getEvidenceError(fmt.Errorf("failed to shutdown GPU evidence collector: %v", shutdownErr))
	}

	encodedEvidence, err := encodeEvidence(in.ContentType, in.Nonce, devices)
	if err != nil {
		return getEvidenceError(err)
	}

	return &compositor.EvidenceOut{
		Status:   statusSucceeded,
		Evidence: encodedEvidence,
	}
}

func supportsFormat(contentType string) bool {
	for _, format := range supportedFormats {
		if format.ContentType == contentType {
			return true
		}
	}

	return false
}

func validateOptions(options []byte) error {
	if len(options) == 0 || string(options) == "null" {
		return nil
	}

	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(options, &parsed); err != nil {
		return fmt.Errorf("failed to parse %s: %v", options, err)
	}

	if len(parsed) > 0 {
		return fmt.Errorf("gpu attester does not support options")
	}

	return nil
}

func encodeEvidence(contentType string, nonce []byte, devices []nvgpu.GPUDevice) ([]byte, error) {
	token := &tokens.GPUEvidence{
		Nonce:   nonce,
		Devices: make([]tokens.GPUDeviceEvidence, len(devices)),
	}

	for i, device := range devices {
		certChain, err := device.Certificate().EncodeBase64()
		if err != nil {
			return nil, fmt.Errorf("failed to encode GPU certificate chain for device %d: %v", i, err)
		}

		token.Devices[i] = tokens.GPUDeviceEvidence{
			Arch:              device.Arch(),
			AttestationReport: device.AttestationReport(),
			CertificateChain:  certChain,
		}
	}

	switch contentType {
	case ApplicationvndVeraisonNvGpuEvidenceJSON:
		encodedEvidence, err := token.ToJSON()
		if err != nil {
			return nil, fmt.Errorf("failed to JSON encode GPU evidence: %v", err)
		}
		return encodedEvidence, nil
	case ApplicationvndVeraisonNvGpuEvidenceCBOR:
		encodedEvidence, err := token.ToCBOR()
		if err != nil {
			return nil, fmt.Errorf("failed to CBOR encode GPU evidence: %v", err)
		}
		return encodedEvidence, nil
	default:
		return nil, fmt.Errorf("no supported format in gpu plugin matches the requested format")
	}
}
