// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package ratsdtoken

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/veraison/eat"
)

const (
	LegacyProfile = "tag:github.com,2024:veraison/ratsd"
	LegacyCMWType = "tag:github.com,2025:veraison/ratsd/cmw"

	NonceAdjustFunctionShake128 = "shake-128"
	NonceAdjustFunctionShake256 = "shake-256"
)

// Evidence exposes the legacy RATSD token as a single claims container.
type Evidence struct {
	Claims claims `json:"-"`
}

// claims contains the legacy RATSD token claims defined in docs/ratsd-token.cddl.
type claims struct {
	EatProfile          *eat.Profile    `json:"eat_profile"`
	EatNonce            *eat.Nonce      `json:"eat_nonce"`
	CMW                 string          `json:"cmw"`
	NonceAdjustFunction *string         `json:"vnd.veraison.nonce_adjust_function,omitempty"`
	NonceAdjustMap      map[string]uint `json:"vnd.veraison.nonce_adjust_map,omitempty"`
}

// SetNonce replaces the stored EAT nonce with the supplied raw nonce value.
func (c *claims) SetNonce(v []byte) error {
	if c == nil {
		return errors.New("nil claims")
	}

	var nonce eat.Nonce
	if err := nonce.Add(v); err != nil {
		return err
	}

	c.EatNonce = &nonce
	return nil
}

// SetNonceAdjustFn sets the nonce adjustment algorithm.
func (c *claims) SetNonceAdjustFn(alg string) error {
	if c == nil {
		return errors.New("nil claims")
	}

	switch alg {
	case NonceAdjustFunctionShake128, NonceAdjustFunctionShake256:
		c.NonceAdjustFunction = &alg
		return nil
	case "":
		return errors.New(`invalid claim "vnd.veraison.nonce_adjust_function": empty value`)
	default:
		return fmt.Errorf(`invalid claim "vnd.veraison.nonce_adjust_function": %q`, alg)
	}
}

// SetKeyandNonceSz sets the nonce-adjusted size for a given key.
func (c *claims) SetKeyandNonceSz(key string, sz uint) error {
	if c == nil {
		return errors.New("nil claims")
	}

	if key == "" {
		return errors.New(`invalid claim "vnd.veraison.nonce_adjust_map": empty key`)
	}

	if c.NonceAdjustMap == nil {
		c.NonceAdjustMap = make(map[string]uint)
	}

	c.NonceAdjustMap[key] = sz
	return nil
}

// NewEvidence returns an Evidence with the legacy EAT profile preset.
func NewEvidence() *Evidence {
	profile, err := eat.NewProfile(LegacyProfile)
	if err != nil {
		panic(fmt.Sprintf("invalid legacy EAT profile constant: %v", err))
	}

	return &Evidence{
		Claims: claims{
			EatProfile: profile,
		},
	}
}

// Valid checks whether the Evidence matches the legacy RATSD token shape.
func (e *Evidence) Valid() error {
	if e == nil {
		return errors.New("nil evidence")
	}

	c := e.Claims

	if c.EatProfile == nil {
		return errors.New(`missing mandatory claim "eat_profile"`)
	}

	profile, err := c.EatProfile.Get()
	if err != nil {
		return errors.New(`missing mandatory claim "eat_profile"`)
	}

	if profile != LegacyProfile {
		return fmt.Errorf(`invalid claim "eat_profile": expected %q`, LegacyProfile)
	}

	if c.EatNonce == nil || c.EatNonce.Len() == 0 {
		return errors.New(`missing mandatory claim "eat_nonce"`)
	}

	if err := c.EatNonce.Validate(); err != nil {
		return fmt.Errorf(`invalid claim "eat_nonce": %w`, err)
	}

	if c.CMW == "" {
		return errors.New(`missing mandatory claim "cmw"`)
	}

	if c.NonceAdjustFunction != nil {
		if *c.NonceAdjustFunction == "" {
			return errors.New(`invalid claim "vnd.veraison.nonce_adjust_function": empty value`)
		}

		if *c.NonceAdjustFunction != NonceAdjustFunctionShake128 &&
			*c.NonceAdjustFunction != NonceAdjustFunctionShake256 {
			return fmt.Errorf(`invalid claim "vnd.veraison.nonce_adjust_function": %q`, *c.NonceAdjustFunction)
		}

		if c.NonceAdjustMap == nil {
			return errors.New(`missing mandatory claim "vnd.veraison.nonce_adjust_map"`)
		}
	}

	if c.NonceAdjustMap != nil {
		if len(c.NonceAdjustMap) == 0 {
			return errors.New(`invalid claim "vnd.veraison.nonce_adjust_map": must contain at least one entry`)
		}

		if c.NonceAdjustFunction == nil {
			return errors.New(`missing mandatory claim "vnd.veraison.nonce_adjust_function"`)
		}
	}

	return nil
}

// MarshalJSON encodes Evidence using the flat legacy claim layout.
func (e Evidence) MarshalJSON() ([]byte, error) {
	if err := e.Valid(); err != nil {
		return nil, fmt.Errorf("JSON encoding failed: %w", err)
	}

	return json.Marshal(e.Claims)
}

// UnmarshalJSON decodes Evidence from the flat legacy claim layout.
func (e *Evidence) UnmarshalJSON(data []byte) error {
	var decoded claims
	if err := json.Unmarshal(data, &decoded); err != nil {
		return fmt.Errorf("JSON decoding failed: %w", err)
	}

	tmp := Evidence{Claims: decoded}
	if err := tmp.Valid(); err != nil {
		return fmt.Errorf("JSON decoding failed: %w", err)
	}

	*e = tmp
	return nil
}
