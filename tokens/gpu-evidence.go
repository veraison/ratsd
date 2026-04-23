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
	Arch              string       `json:"arch"`
	AttestationReport BinaryString `json:"attestation_report"`
	CertificateChain  string       `json:"certificate_chain"`
}

type GPUEvidence struct {
	Nonce   BinaryString        `json:"nonce"`
	Devices []GPUDeviceEvidence `json:"devices"`
}

func (g *GPUEvidence) Valid() error {
	if len(g.Nonce) == 0 {
		return errors.New(`missing mandatory field "nonce"`)
	}

	if len(g.Devices) == 0 {
		return errors.New(`missing mandatory field "devices"`)
	}

	for i, device := range g.Devices {
		if device.Arch == "" {
			return fmt.Errorf(`missing mandatory field "devices[%d].arch"`, i)
		}
		if len(device.AttestationReport) == 0 {
			return fmt.Errorf(`missing mandatory field "devices[%d].attestation_report"`, i)
		}
		if device.CertificateChain == "" {
			return fmt.Errorf(`missing mandatory field "devices[%d].certificate_chain"`, i)
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
