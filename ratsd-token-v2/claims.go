// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package ratsdtokenv2

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/eat"
)

const (
	NonceAdjustFunctionShake128 = "shake-128"
	NonceAdjustFunctionShake256 = "shake-256"

	claimsTagNumber = 601

	claimLabelEatProfile          = 265
	claimLabelEatNonce            = 10
	claimLabelNonceAdjustFunction = -65537
	claimLabelNonceAdjustMap      = -65538
)

// Claims contains the tagged EAT claims embedded in the RATSD CMW collection.
type Claims struct {
	EatProfile          string
	EatNonce            []byte
	NonceAdjustFunction *string
	NonceAdjustMap      map[string]uint
}

// SetNonce replaces the stored EAT nonce with the supplied raw nonce value.
func (c *Claims) SetNonce(v []byte) error {
	if c == nil {
		return errNilClaims
	}

	if err := validateNonce(v); err != nil {
		return err
	}

	c.EatNonce = cloneBytes(v)
	return nil
}

// GetEatNonce returns a copy of the EAT nonce claim.
func (c Claims) GetEatNonce() []byte {
	return cloneBytes(c.EatNonce)
}

// GetEatProfile returns the EAT profile claim.
func (c Claims) GetEatProfile() string {
	return c.EatProfile
}

// SetNonceAdjustFn sets the nonce adjustment algorithm.
func (c *Claims) SetNonceAdjustFn(alg string) error {
	if c == nil {
		return errNilClaims
	}

	switch alg {
	case NonceAdjustFunctionShake128, NonceAdjustFunctionShake256:
		c.NonceAdjustFunction = &alg
		return nil
	case "":
		return errEmptyNonceAdjustFunction
	default:
		return fmt.Errorf(`invalid claim "nonce_adjust_function": %q`, alg)
	}
}

// GetNonceAdjustFn returns the nonce adjustment algorithm, if set.
func (c Claims) GetNonceAdjustFn() string {
	if c.NonceAdjustFunction == nil {
		return ""
	}

	return *c.NonceAdjustFunction
}

// SetKeyandNonceSz sets the nonce-adjusted size for a given key.
func (c *Claims) SetKeyandNonceSz(key string, sz uint) error {
	if c == nil {
		return errNilClaims
	}

	if key == "" {
		return errEmptyNonceAdjustMapKey
	}

	if c.NonceAdjustMap == nil {
		c.NonceAdjustMap = make(map[string]uint)
	}

	c.NonceAdjustMap[key] = sz
	return nil
}

// GetKeyandNonceSz returns the configured adjusted nonce size for the given key.
func (c Claims) GetKeyandNonceSz(key string) (uint, bool) {
	if c.NonceAdjustMap == nil {
		return 0, false
	}

	sz, ok := c.NonceAdjustMap[key]
	return sz, ok
}

// GetNonceAdjustMap returns a copy of the nonce adjustment map.
func (c Claims) GetNonceAdjustMap() map[string]uint {
	return cloneNonceAdjustMap(c.NonceAdjustMap)
}

// Valid checks whether the Claims match the RATSD v2 token shape.
func (c Claims) Valid() error {
	if c.EatProfile == "" {
		return errMissingEatProfile
	}

	if c.EatProfile != Profile {
		return fmt.Errorf(`invalid claim "eat_profile": expected %q`, Profile)
	}

	if c.EatNonce == nil || len(c.EatNonce) == 0 {
		return errMissingEatNonce
	}

	if err := validateNonce(c.EatNonce); err != nil {
		return fmt.Errorf(`invalid claim "eat_nonce": %w`, err)
	}

	if c.NonceAdjustFunction != nil {
		if *c.NonceAdjustFunction == "" {
			return errEmptyNonceAdjustFunction
		}

		if *c.NonceAdjustFunction != NonceAdjustFunctionShake128 &&
			*c.NonceAdjustFunction != NonceAdjustFunctionShake256 {
			return fmt.Errorf(`invalid claim "nonce_adjust_function": %q`, *c.NonceAdjustFunction)
		}
	}

	if c.NonceAdjustMap != nil {
		if c.NonceAdjustFunction == nil {
			return errMissingNonceAdjustFunction
		}

		for key := range c.NonceAdjustMap {
			if key == "" {
				return errEmptyNonceAdjustMapKey
			}
		}
	}

	return nil
}

// MarshalCBOR encodes the tagged Lead Attester claims, inside RATSD
func (c Claims) MarshalCBOR() ([]byte, error) {
	if err := c.Valid(); err != nil {
		return nil, err
	}

	claims := map[int64]any{
		claimLabelEatProfile: c.EatProfile,
		claimLabelEatNonce:   bytesOrEmpty(c.EatNonce),
	}

	if c.NonceAdjustFunction != nil {
		claims[claimLabelNonceAdjustFunction] = *c.NonceAdjustFunction
	}

	if c.NonceAdjustMap != nil {
		claims[claimLabelNonceAdjustMap] = cloneNonceAdjustMap(c.NonceAdjustMap)
	}

	content, err := encMode.Marshal(claims)
	if err != nil {
		return nil, err
	}

	return cbor.RawTag{
		Number:  claimsTagNumber,
		Content: content,
	}.MarshalCBOR()
}

// UnmarshalCBOR decodes the tagged RATSD claims.
func (c *Claims) UnmarshalCBOR(data []byte) error {
	if c == nil {
		return errNilClaims
	}

	var tag cbor.RawTag
	if err := tag.UnmarshalCBOR(data); err != nil {
		return err
	}

	if tag.Number != claimsTagNumber {
		return fmt.Errorf("invalid RATSD claims tag %d", tag.Number)
	}

	var raw map[any]cbor.RawMessage
	if err := decMode.Unmarshal(tag.Content, &raw); err != nil {
		return err
	}

	var decoded Claims
	seen := make(map[int64]bool)
	for key, value := range raw {
		label, ok := int64Label(key)
		if !ok {
			return fmt.Errorf("invalid RATSD claims label: %v", key)
		}

		if seen[label] {
			return fmt.Errorf("duplicate RATSD claims label: %d", label)
		}
		seen[label] = true

		switch label {
		case claimLabelEatProfile:
			if err := decMode.Unmarshal(value, &decoded.EatProfile); err != nil {
				return fmt.Errorf(`invalid claim "eat_profile": %w`, err)
			}
		case claimLabelEatNonce:
			if err := decMode.Unmarshal(value, &decoded.EatNonce); err != nil {
				return fmt.Errorf(`invalid claim "eat_nonce": %w`, err)
			}
			decoded.EatNonce = bytesOrEmpty(decoded.EatNonce)
		case claimLabelNonceAdjustFunction:
			var alg string
			if err := decMode.Unmarshal(value, &alg); err != nil {
				return fmt.Errorf(`invalid claim "nonce_adjust_function": %w`, err)
			}
			decoded.NonceAdjustFunction = &alg
		case claimLabelNonceAdjustMap:
			var sizes map[string]uint
			if err := decMode.Unmarshal(value, &sizes); err != nil {
				return fmt.Errorf(`invalid claim "nonce_adjust_map": %w`, err)
			}
			decoded.NonceAdjustMap = cloneNonceAdjustMap(sizes)
		default:
			return fmt.Errorf("invalid RATSD claims label: %d", label)
		}
	}

	if err := decoded.Valid(); err != nil {
		return err
	}

	*c = decoded
	return nil
}

func validateNonce(v []byte) error {
	nonceSize := len(v)
	if nonceSize < eat.MinNonceSize || nonceSize > eat.MaxNonceSize {
		return fmt.Errorf(
			"a nonce must be between %d and %d bytes long; found %d",
			eat.MinNonceSize, eat.MaxNonceSize, nonceSize,
		)
	}

	return nil
}

func cloneClaims(c Claims) Claims {
	clone := Claims{
		EatProfile: c.EatProfile,
		EatNonce:   cloneBytes(c.EatNonce),
	}

	if c.NonceAdjustFunction != nil {
		nonceAdjustFunction := *c.NonceAdjustFunction
		clone.NonceAdjustFunction = &nonceAdjustFunction
	}

	if c.NonceAdjustMap != nil {
		clone.NonceAdjustMap = cloneNonceAdjustMap(c.NonceAdjustMap)
	}

	return clone
}

func cloneNonceAdjustMap(v map[string]uint) map[string]uint {
	if v == nil {
		return nil
	}

	clone := make(map[string]uint, len(v))
	for k, value := range v {
		clone[k] = value
	}

	return clone
}
