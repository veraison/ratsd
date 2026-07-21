// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package tokens

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
)

const (
	GPUEvidenceMediaTypeJSON = "application/vnd.veraison.nvidia-gpu-evidence+json"

	gpuEvidenceNonceSize = nvml.CC_GPU_CEC_NONCE_SIZE
)

type GPUDeviceEvidence struct {
	Nonce             []byte `json:"nonce"`
	Arch              string `json:"arch"`
	AttestationReport []byte `json:"evidence"`
	CertificateChain  string `json:"certificate"`
}

type GPUEvidence struct {
	Devices []GPUDeviceEvidence `json:"devices"`
}

func (g GPUEvidence) Valid() error {
	if len(g.Devices) == 0 {
		return errors.New("missing mandatory GPU evidence device")
	}

	for i, device := range g.Devices {
		if len(device.Nonce) == 0 {
			return fmt.Errorf(`missing mandatory field "[%d].nonce"`, i)
		}
		if len(device.Nonce) != gpuEvidenceNonceSize {
			return fmt.Errorf(`invalid field "[%d].nonce": expected %d bytes, got %d`, i, gpuEvidenceNonceSize, len(device.Nonce))
		}
		if device.Arch == "" {
			return fmt.Errorf(`missing mandatory field "[%d].arch"`, i)
		}
		if device.Arch != "BLACKWELL" && device.Arch != "HOPPER" {
			return fmt.Errorf(`invalid field "[%d].arch": expected "BLACKWELL" or "HOPPER", got %q`, i, device.Arch)
		}
		if len(device.AttestationReport) == 0 {
			return fmt.Errorf(`missing mandatory field "[%d].evidence"`, i)
		}
		if device.CertificateChain == "" {
			return fmt.Errorf(`missing mandatory field "[%d].certificate"`, i)
		}
		if _, err := base64.StdEncoding.DecodeString(device.CertificateChain); err != nil {
			return fmt.Errorf(`invalid field "[%d].certificate": %w`, i, err)
		}
	}

	return nil
}

func (g *GPUEvidence) ToJSON() ([]byte, error) {
	if g == nil {
		return nil, errors.New("JSON encoding failed: nil GPU evidence")
	}

	if err := g.Valid(); err != nil {
		return nil, fmt.Errorf("JSON encoding failed: %w", err)
	}

	return json.Marshal(g.Devices)
}

func (g *GPUEvidence) FromJSON(data []byte) error {
	if g == nil {
		return errors.New("JSON decoding failed: nil GPU evidence")
	}

	if err := json.Unmarshal(data, &g.Devices); err != nil {
		return fmt.Errorf("JSON decoding failed: %w", err)
	}

	if err := g.Valid(); err != nil {
		return fmt.Errorf("JSON decoding failed: %w", err)
	}

	return nil
}
