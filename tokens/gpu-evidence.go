// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package tokens

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const (
	GPUEvidenceMediaTypeCBOR = "application/vnd.veraison.nv-gpu-evidence+cbor"
	GPUEvidenceMediaTypeJSON = "application/vnd.veraison.nv-gpu-evidence+json"
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

func (g *GPUEvidence) Valid() error {
	if len(g.Devices) == 0 {
		return errors.New(`missing mandatory field "devices"`)
	}

	for i, device := range g.Devices {
		if len(device.Nonce) == 0 {
			return fmt.Errorf(`missing mandatory field "devices[%d].nonce"`, i)
		}
		if device.Arch == "" {
			return fmt.Errorf(`missing mandatory field "devices[%d].arch"`, i)
		}
		if len(device.AttestationReport) == 0 {
			return fmt.Errorf(`missing mandatory field "devices[%d].evidence"`, i)
		}
		if device.CertificateChain == "" {
			return fmt.Errorf(`missing mandatory field "devices[%d].certificate"`, i)
		}
	}

	return nil
}

func (g *GPUEvidence) ToJSON() ([]byte, error) {
	if err := g.Valid(); err != nil {
		return nil, fmt.Errorf("JSON encoding failed: %w", err)
	}

	return json.Marshal(g)
}

func (g *GPUEvidence) FromJSON(data []byte) error {
	if err := json.Unmarshal(data, g); err != nil {
		return fmt.Errorf("JSON decoding failed: %w", err)
	}

	if err := g.Valid(); err != nil {
		return fmt.Errorf("JSON decoding failed: %w", err)
	}

	return nil
}

func (g *GPUEvidence) ToCBOR() ([]byte, error) {
	if err := g.Valid(); err != nil {
		return nil, fmt.Errorf("CBOR encoding failed: %w", err)
	}

	return cbor.Marshal(g)
}

func (g *GPUEvidence) FromCBOR(data []byte) error {
	if err := cbor.Unmarshal(data, g); err != nil {
		return fmt.Errorf("CBOR decoding failed: %w", err)
	}

	if err := g.Valid(); err != nil {
		return fmt.Errorf("CBOR decoding failed: %w", err)
	}

	return nil
}
