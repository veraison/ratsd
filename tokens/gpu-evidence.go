// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package tokens

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const (
	GPUEvidenceMediaTypeCBOR = "application/vnd.veraison.nv-gpu-evidence+cbor"
	GPUEvidenceMediaTypeJSON = "application/vnd.veraison.nv-gpu-evidence+json"

	gpuEvidenceNonceSize = 32
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

type gpuDeviceEvidenceWire struct {
	Arch              string `json:"arch"`
	CertificateChain  string `json:"certificate"`
	AttestationReport string `json:"evidence"`
	Nonce             string `json:"nonce"`
}

func (g *GPUEvidence) Valid() error {
	if g == nil {
		return errors.New("nil GPU evidence")
	}

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

func (g GPUEvidence) MarshalJSON() ([]byte, error) {
	wireDevices, err := g.toWireDevices()
	if err != nil {
		return nil, err
	}

	return json.Marshal(wireDevices)
}

func (g *GPUEvidence) UnmarshalJSON(data []byte) error {
	if g == nil {
		return errors.New("nil GPU evidence")
	}

	var wireDevices []gpuDeviceEvidenceWire
	if err := json.Unmarshal(data, &wireDevices); err != nil {
		return err
	}

	decoded, err := gpuEvidenceFromWireDevices(wireDevices)
	if err != nil {
		return err
	}

	*g = decoded
	return nil
}

func (g GPUEvidence) MarshalCBOR() ([]byte, error) {
	wireDevices, err := g.toWireDevices()
	if err != nil {
		return nil, err
	}

	return cbor.Marshal(wireDevices)
}

func (g *GPUEvidence) UnmarshalCBOR(data []byte) error {
	if g == nil {
		return errors.New("nil GPU evidence")
	}

	var wireDevices []gpuDeviceEvidenceWire
	if err := cbor.Unmarshal(data, &wireDevices); err != nil {
		return err
	}

	decoded, err := gpuEvidenceFromWireDevices(wireDevices)
	if err != nil {
		return err
	}

	*g = decoded
	return nil
}

func (g GPUEvidence) toWireDevices() ([]gpuDeviceEvidenceWire, error) {
	if err := (&g).Valid(); err != nil {
		return nil, err
	}

	wireDevices := make([]gpuDeviceEvidenceWire, len(g.Devices))
	for i, device := range g.Devices {
		wireDevices[i] = gpuDeviceEvidenceWire{
			Arch:              device.Arch,
			CertificateChain:  device.CertificateChain,
			AttestationReport: base64.StdEncoding.EncodeToString(device.AttestationReport),
			Nonce:             hex.EncodeToString(device.Nonce),
		}
	}

	return wireDevices, nil
}

func gpuEvidenceFromWireDevices(wireDevices []gpuDeviceEvidenceWire) (GPUEvidence, error) {
	evidence := GPUEvidence{
		Devices: make([]GPUDeviceEvidence, len(wireDevices)),
	}

	for i, wireDevice := range wireDevices {
		nonce, err := hex.DecodeString(wireDevice.Nonce)
		if err != nil {
			return GPUEvidence{}, fmt.Errorf(`invalid field "[%d].nonce": %w`, i, err)
		}

		report, err := base64.StdEncoding.DecodeString(wireDevice.AttestationReport)
		if err != nil {
			return GPUEvidence{}, fmt.Errorf(`invalid field "[%d].evidence": %w`, i, err)
		}

		evidence.Devices[i] = GPUDeviceEvidence{
			Nonce:             nonce,
			Arch:              wireDevice.Arch,
			AttestationReport: report,
			CertificateChain:  wireDevice.CertificateChain,
		}
	}

	if err := evidence.Valid(); err != nil {
		return GPUEvidence{}, err
	}

	return evidence, nil
}
