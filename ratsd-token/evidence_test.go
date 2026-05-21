// Copyright 2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package ratsdtoken

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/veraison/eat"
)

func validEvidence() *Evidence {
	profile, err := eat.NewProfile(LegacyProfile)
	if err != nil {
		panic(err)
	}

	var claimSet Claims
	if err := claimSet.SetNonce([]byte("12345678")); err != nil {
		panic(err)
	}
	claimSet.EatProfile = profile
	claimSet.CMW = "ZXhhbXBsZS1jbXc"

	return &Evidence{
		Claims: claimSet,
	}
}
func assertEvidenceEquivalent(t *testing.T, expected, actual *Evidence) {
	t.Helper()

	if assert.NotNil(t, expected.Claims.EatProfile) && assert.NotNil(t, actual.Claims.EatProfile) {
		expectedProfile, err := expected.Claims.EatProfile.Get()
		assert.NoError(t, err)
		actualProfile, err := actual.Claims.EatProfile.Get()
		assert.NoError(t, err)
		assert.Equal(t, expectedProfile, actualProfile)
	}

	if assert.NotNil(t, expected.Claims.EatNonce) && assert.NotNil(t, actual.Claims.EatNonce) {
		assert.Equal(t, expected.Claims.EatNonce.Len(), actual.Claims.EatNonce.Len())
		for i := 0; i < expected.Claims.EatNonce.Len(); i++ {
			assert.Equal(t, expected.Claims.EatNonce.GetI(i), actual.Claims.EatNonce.GetI(i))
		}
	}

	assert.Equal(t, expected.Claims.NonceAdjustFunction, actual.Claims.NonceAdjustFunction)
	assert.Equal(t, expected.Claims.NonceAdjustMap, actual.Claims.NonceAdjustMap)
	assert.Equal(t, expected.Claims.CMW, actual.Claims.CMW)
}

func TestNewEvidence(t *testing.T) {
	evidence := NewEvidence()

	if assert.NotNil(t, evidence.Claims.EatProfile) {
		profile, err := evidence.Claims.EatProfile.Get()
		assert.NoError(t, err)
		assert.Equal(t, LegacyProfile, profile)
	}
}

func TestClaimsSetNonce(t *testing.T) {
	var claimSet Claims

	assert.NoError(t, claimSet.SetNonce([]byte("abcdefgh")))
	if assert.NotNil(t, claimSet.EatNonce) {
		assert.Equal(t, 1, claimSet.EatNonce.Len())
		assert.Equal(t, []byte("abcdefgh"), claimSet.EatNonce.GetI(0))
	}
}

func TestClaimsSetNonceFail(t *testing.T) {
	var claimSet Claims

	assert.EqualError(t, claimSet.SetNonce([]byte("short")), "a nonce must be between 8 and 64 bytes long; found 5")
	assert.Nil(t, claimSet.EatNonce)
}

func TestClaimsSetNonceAdjustFn(t *testing.T) {
	var claimSet Claims

	assert.NoError(t, claimSet.SetNonceAdjustFn(NonceAdjustFunctionShake256))
	if assert.NotNil(t, claimSet.NonceAdjustFunction) {
		assert.Equal(t, NonceAdjustFunctionShake256, *claimSet.NonceAdjustFunction)
	}
}

func TestClaimsSetNonceAdjustFnFail(t *testing.T) {
	var claimSet Claims

	assert.EqualError(t, claimSet.SetNonceAdjustFn("sha-256"), `invalid claim "vnd.veraison.nonce_adjust_function": "sha-256"`)
	assert.Nil(t, claimSet.NonceAdjustFunction)
}

func TestClaimsSetKeyandNonceSz(t *testing.T) {
	var claimSet Claims

	assert.NoError(t, claimSet.SetKeyandNonceSz("configfs-tsm", 32))
	assert.Equal(t, map[string]uint{"configfs-tsm": 32}, claimSet.NonceAdjustMap)
}

func TestClaimsSetKeyandNonceSzFail(t *testing.T) {
	var claimSet Claims

	assert.EqualError(t, claimSet.SetKeyandNonceSz("", 32), `invalid claim "vnd.veraison.nonce_adjust_map": empty key`)
	assert.Nil(t, claimSet.NonceAdjustMap)
}

func TestEvidenceValidPass(t *testing.T) {
	evidence := validEvidence()

	assert.NoError(t, evidence.Valid())
}

func TestEvidenceValidFailWrongProfile(t *testing.T) {
	evidence := validEvidence()
	profile, err := eat.NewProfile("tag:github.com,2026:veraison/ratsd/v2")
	assert.NoError(t, err)
	evidence.Claims.EatProfile = profile

	assert.EqualError(t, evidence.Valid(), `invalid claim "eat_profile": expected "tag:github.com,2024:veraison/ratsd"`)
}

func TestEvidenceValidFailIncompleteNonceAdjustGroup(t *testing.T) {
	evidence := validEvidence()
	fn := NonceAdjustFunctionShake256
	evidence.Claims.NonceAdjustFunction = &fn

	assert.EqualError(t, evidence.Valid(), `missing mandatory claim "vnd.veraison.nonce_adjust_map"`)
}

func TestEvidenceJSONSerDesPass(t *testing.T) {
	evidence := validEvidence()
	fn := NonceAdjustFunctionShake128
	evidence.Claims.NonceAdjustFunction = &fn
	evidence.Claims.NonceAdjustMap = map[string]uint{
		"configfs-tsm": 32,
	}

	encodedJSON, err := json.Marshal(evidence)
	assert.NoError(t, err)

	var encodedClaims map[string]any
	assert.NoError(t, json.Unmarshal(encodedJSON, &encodedClaims))
	assert.Equal(t, LegacyProfile, encodedClaims["eat_profile"])
	assert.Equal(t, "MTIzNDU2Nzg=", encodedClaims["eat_nonce"])
	assert.Equal(t, evidence.Claims.CMW, encodedClaims["cmw"])
	assert.NotContains(t, encodedClaims, "claims")

	decodedEvidence := &Evidence{}
	assert.NoError(t, json.Unmarshal(encodedJSON, decodedEvidence))
	assertEvidenceEquivalent(t, evidence, decodedEvidence)
}
