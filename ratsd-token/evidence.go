// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package ratsdtoken

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/veraison/cmw"
	"github.com/veraison/eat"
)

const (
	LegacyProfile = "tag:github.com,2024:veraison/ratsd"

	NonceAdjustFunctionShake128 = "shake-128"
	NonceAdjustFunctionShake256 = "shake-256"
)

var (
	errNilEvidence                = errors.New("nil evidence")
	errNilClaims                  = errors.New("nil claims")
	errNilCMWValue                = errors.New(`invalid claim "cmw": nil value`)
	errEmptyNonceAdjustFunction   = errors.New(`invalid claim "vnd.veraison.nonce_adjust_function": empty value`)
	errEmptyNonceAdjustMapKey     = errors.New(`invalid claim "vnd.veraison.nonce_adjust_map": empty key`)
	errMissingEatProfile          = errors.New(`missing mandatory claim "eat_profile"`)
	errMissingEatNonce            = errors.New(`missing mandatory claim "eat_nonce"`)
	errMissingCMW                 = errors.New(`missing mandatory claim "cmw"`)
	errMissingNonceAdjustFunction = errors.New(`missing mandatory claim "vnd.veraison.nonce_adjust_function"`)
)

// Evidence exposes the legacy RATSD token as a single claims container.
type Evidence struct {
	Claims Claims `json:"-"`
}

// SetClaims attaches the supplied claims to the Evidence instance.
// Only successfully validated claims are allowed to be set.
func (e *Evidence) SetClaims(c Claims) error {
	if e == nil {
		return errNilEvidence
	}

	tmp := Evidence{Claims: c}
	if err := tmp.Valid(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	e.Claims = c
	return nil
}

// GetClaims returns a copy of the stored claims after validating the evidence state.
func (e Evidence) GetClaims() (c Claims, err error) {
	if err = e.Valid(); err != nil {
		return c, fmt.Errorf("validation failed: %w", err)
	}

	c, err = cloneClaims(e.Claims)
	if err != nil {
		return c, fmt.Errorf("claims copy failed: %w", err)
	}

	return c, nil
}

// Claims contains the legacy RATSD token claims defined in docs/ratsd-token.cddl.
type Claims struct {
	EatProfile          *eat.Profile    `json:"eat_profile"`
	EatNonce            *eat.Nonce      `json:"eat_nonce"`
	CMW                 string          `json:"cmw"`
	NonceAdjustFunction *string         `json:"vnd.veraison.nonce_adjust_function,omitempty"`
	NonceAdjustMap      map[string]uint `json:"vnd.veraison.nonce_adjust_map,omitempty"`
}

func cloneClaims(c Claims) (Claims, error) {
	clone := Claims{
		CMW: c.CMW,
	}

	if c.EatProfile != nil {
		profile, err := cloneEatProfile(c.EatProfile)
		if err != nil {
			return clone, fmt.Errorf(`invalid claim "eat_profile": %w`, err)
		}
		clone.EatProfile = profile
	}

	if c.EatNonce != nil {
		nonce, err := cloneEatNonce(c.EatNonce)
		if err != nil {
			return clone, fmt.Errorf(`invalid claim "eat_nonce": %w`, err)
		}
		clone.EatNonce = nonce
	}

	if c.NonceAdjustFunction != nil {
		nonceAdjustFunction := *c.NonceAdjustFunction
		clone.NonceAdjustFunction = &nonceAdjustFunction
	}

	if c.NonceAdjustMap != nil {
		clone.NonceAdjustMap = cloneNonceAdjustMap(c.NonceAdjustMap)
	}

	return clone, nil
}

func cloneEatProfile(v *eat.Profile) (*eat.Profile, error) {
	profileValue, err := v.Get()
	if err != nil {
		return nil, err
	}

	return eat.NewProfile(profileValue)
}

func cloneEatNonce(v *eat.Nonce) (*eat.Nonce, error) {
	var nonce eat.Nonce
	for i := 0; i < v.Len(); i++ {
		value := v.GetI(i)
		if err := nonce.Add(append([]byte(nil), value...)); err != nil {
			return nil, err
		}
	}

	return &nonce, nil
}

func cloneNonceAdjustMap(v map[string]uint) map[string]uint {
	clone := make(map[string]uint, len(v))
	for k, value := range v {
		clone[k] = value
	}

	return clone
}

// GetEatProfile returns the EAT profile claim.
func (c Claims) GetEatProfile() *eat.Profile {
	if c.EatProfile == nil {
		return nil
	}

	profile, err := cloneEatProfile(c.EatProfile)
	if err != nil {
		return nil
	}

	return profile
}

// GetEatNonce returns the EAT nonce claim.
func (c Claims) GetEatNonce() *eat.Nonce {
	if c.EatNonce == nil {
		return nil
	}

	nonce, err := cloneEatNonce(c.EatNonce)
	if err != nil {
		return nil
	}

	return nonce
}

// GetCMW returns the legacy CMW collection claim.
func (c Claims) GetCMW() *cmw.CMW {
	if c.CMW == "" {
		return nil
	}

	decoded, err := decodeLegacyCMW(c.CMW)
	if err != nil {
		return nil
	}

	return decoded
}

// GetNonceAdjustFn returns the nonce adjustment algorithm, if set.
func (c Claims) GetNonceAdjustFn() string {
	if c.NonceAdjustFunction == nil {
		return ""
	}

	return *c.NonceAdjustFunction
}

// GetNonceAdjustMap returns a copy of the nonce adjustment map.
func (c Claims) GetNonceAdjustMap() map[string]uint {
	if c.NonceAdjustMap == nil {
		return nil
	}

	return cloneNonceAdjustMap(c.NonceAdjustMap)
}

// GetKeyandNonceSz returns the configured adjusted nonce size for the given key.
// The boolean result reports whether the key was present in the nonce-adjust map.
func (c Claims) GetKeyandNonceSz(key string) (uint, bool) {
	if c.NonceAdjustMap == nil {
		return 0, false
	}

	sz, ok := c.NonceAdjustMap[key]
	return sz, ok
}

// SetCMW serializes the supplied CMW object into the legacy base64 claim form.
func (c *Claims) SetCMW(v interface{}) error {
	if c == nil {
		return errNilClaims
	}

	if v == nil {
		return errNilCMWValue
	}

	cmwValue, err := toCMW(v)
	if err != nil {
		return err
	}

	encoded, err := cmwValue.MarshalJSON()
	if err != nil {
		return fmt.Errorf(`invalid claim "cmw": %w`, err)
	}

	c.CMW = base64.StdEncoding.EncodeToString(encoded)
	return nil
}

// SetNonce replaces the stored EAT nonce with the supplied raw nonce value.
func (c *Claims) SetNonce(v []byte) error {
	if c == nil {
		return errNilClaims
	}

	var nonce eat.Nonce
	if err := nonce.Add(v); err != nil {
		return err
	}

	c.EatNonce = &nonce
	return nil
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
		return fmt.Errorf(`invalid claim "vnd.veraison.nonce_adjust_function": %q`, alg)
	}
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

func decodeLegacyCMW(v string) (*cmw.CMW, error) {
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("CMW base64 decoding failed: %w", err)
	}

	var decoded cmw.CMW
	if err := decoded.UnmarshalJSON(b); err != nil {
		return nil, fmt.Errorf("CMW JSON decoding failed: %w", err)
	}

	return &decoded, nil
}

func toCMW(v interface{}) (cmw.CMW, error) {
	targetType := reflect.TypeOf(cmw.CMW{})
	value := reflect.ValueOf(v)

	if value.Type().ConvertibleTo(targetType) {
		return value.Convert(targetType).Interface().(cmw.CMW), nil
	}

	if value.Kind() == reflect.Ptr {
		if value.IsNil() {
			return cmw.CMW{}, errNilCMWValue
		}

		elem := value.Elem()
		if elem.Type().ConvertibleTo(targetType) {
			return elem.Convert(targetType).Interface().(cmw.CMW), nil
		}
	}

	return cmw.CMW{}, fmt.Errorf(`invalid claim "cmw": %T`, v)
}

// NewEvidence returns an Evidence with the legacy EAT profile preset.
func NewEvidence() *Evidence {
	profile, err := eat.NewProfile(LegacyProfile)
	if err != nil {
		panic(fmt.Sprintf("invalid legacy EAT profile constant: %v", err))
	}

	return &Evidence{
		Claims: Claims{
			EatProfile: profile,
		},
	}
}

// Valid checks whether the Evidence matches the legacy RATSD token shape.
func (e *Evidence) Valid() error {
	if e == nil {
		return errNilEvidence
	}

	c := e.Claims

	if c.EatProfile == nil {
		return errMissingEatProfile
	}

	profile, err := c.EatProfile.Get()
	if err != nil {
		return errMissingEatProfile
	}

	if profile != LegacyProfile {
		return fmt.Errorf(`invalid claim "eat_profile": expected %q`, LegacyProfile)
	}

	if c.EatNonce == nil || c.EatNonce.Len() == 0 {
		return errMissingEatNonce
	}

	if err := c.EatNonce.Validate(); err != nil {
		return fmt.Errorf(`invalid claim "eat_nonce": %w`, err)
	}

	if c.CMW == "" {
		return errMissingCMW
	}

	if _, err := decodeLegacyCMW(c.CMW); err != nil {
		return fmt.Errorf(`invalid claim "cmw": %w`, err)
	}
	if c.NonceAdjustFunction != nil {
		if *c.NonceAdjustFunction == "" {
			return errEmptyNonceAdjustFunction
		}

		if *c.NonceAdjustFunction != NonceAdjustFunctionShake128 &&
			*c.NonceAdjustFunction != NonceAdjustFunctionShake256 {
			return fmt.Errorf(`invalid claim "vnd.veraison.nonce_adjust_function": %q`, *c.NonceAdjustFunction)
		}
	}

	if c.NonceAdjustMap != nil {
		if c.NonceAdjustFunction == nil {
			return errMissingNonceAdjustFunction
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
	var decoded Claims
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
