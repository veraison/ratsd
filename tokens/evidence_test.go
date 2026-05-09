// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/veraison/cmw"
	cose "github.com/veraison/go-cose"
)

const (
	testCertPath = "../ratsd.crt"
	testKeyPath  = "../ratsd.key"
)

func TestNewEvidence_rejectsUnsupportedTokenVersion(t *testing.T) {
	_, err := NewEvidence(3)
	assert.EqualError(t, err, "unsupported token version 3")
}

func TestEvidenceMarshalLegacy(t *testing.T) {
	evidence, err := NewEvidence(RATSDTokenVersionLegacy)
	assert.NoError(t, err)
	assert.Equal(t, ResponseMediaType(RATSDTokenVersionLegacy), evidence.MediaType())

	nonce := []byte("12345678")
	err = evidence.AddNonce(nonce)
	assert.NoError(t, err)

	err = evidence.AddToken("test-attester", "application/test", []byte("payload"))
	assert.NoError(t, err)

	token, err := evidence.Marshal()
	assert.NoError(t, err)

	var out map[string]string
	err = json.Unmarshal(token, &out)
	assert.NoError(t, err)
	assert.Equal(t, RATSDLegacyProfile, out["eat_profile"])
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(nonce), out["eat_nonce"])

	collectionJSON, err := base64.StdEncoding.DecodeString(out["cmw"])
	assert.NoError(t, err)

	collection := &cmw.CMW{}
	err = collection.UnmarshalJSON(collectionJSON)
	assert.NoError(t, err)

	item, err := collection.GetCollectionItem("test-attester")
	assert.NoError(t, err)
	assert.Equal(t, "application/test", item.GetMonadType())
	assert.Equal(t, []byte("payload"), item.GetMonadValue())
}

func TestEvidenceMarshalCollectionV2(t *testing.T) {
	evidence, err := NewEvidence(RATSDTokenVersionV2)
	assert.NoError(t, err)

	nonce := []byte("12345678")
	err = evidence.AddNonce(nonce)
	assert.NoError(t, err)
	evidence.SetClaim(1000, "custom-claim")

	err = evidence.AddToken("test-attester", "application/test", []byte("payload"))
	assert.NoError(t, err)

	payload, err := evidence.MarshalCollection()
	assert.NoError(t, err)

	collection := &cmw.CMW{}
	err = collection.UnmarshalCBOR(payload)
	assert.NoError(t, err)

	item, err := collection.GetCollectionItem("test-attester")
	assert.NoError(t, err)
	assert.Equal(t, "application/test", item.GetMonadType())
	assert.Equal(t, []byte("payload"), item.GetMonadValue())

	claimsRecord, err := collection.GetCollectionItem(claimsKeyRATSD)
	assert.NoError(t, err)
	assert.Equal(t, RATSDClaimsMediaTypeV2, claimsRecord.GetMonadType())

	var claimsTag cbor.Tag
	err = cbor.Unmarshal(claimsRecord.GetMonadValue(), &claimsTag)
	assert.NoError(t, err)
	assert.Equal(t, uint64(601), claimsTag.Number)

	claimsBytes, err := cbor.Marshal(claimsTag.Content)
	assert.NoError(t, err)

	var claims map[int]any
	err = cbor.Unmarshal(claimsBytes, &claims)
	assert.NoError(t, err)
	assert.Equal(t, RATSDV2Profile, claims[265])
	assert.Equal(t, nonce, claims[10])
	assert.Equal(t, "custom-claim", claims[1000])
}

func TestEvidenceSignUnmarshalAndVerifyV2(t *testing.T) {
	evidence, err := NewEvidence(
		RATSDTokenVersionV2,
		WithSignerPaths(filepath.Join(testCertPath), filepath.Join(testKeyPath)),
	)
	assert.NoError(t, err)

	nonce := []byte("12345678")
	err = evidence.AddNonce(nonce)
	assert.NoError(t, err)
	evidence.SetClaim(1000, "custom-claim")

	err = evidence.AddToken("test-attester", "application/test", []byte("payload"))
	assert.NoError(t, err)

	signer, _, _, err := loadSignerFromPaths(filepath.Join(testCertPath), filepath.Join(testKeyPath))
	assert.NoError(t, err)

	token, err := evidence.Sign(signer)
	assert.NoError(t, err)

	msg := decodeTokenV2(t, token)
	assert.NotEmpty(t, msg.Signature)

	parsed := &Evidence{}
	err = parsed.Unmarshal(token)
	assert.NoError(t, err)
	assert.Equal(t, RATSDTokenVersionV2, parsed.tokenVersion)
	assert.Equal(t, ResponseMediaType(RATSDTokenVersionV2), parsed.MediaType())
	assert.Equal(t, RATSDV2Profile, parsed.Claims()[265])
	assert.Equal(t, nonce, parsed.Claims()[10])
	assert.Equal(t, "custom-claim", parsed.Claims()[1000])
	assert.NotNil(t, parsed.SigningCert)

	item, err := parsed.Collection().GetCollectionItem("test-attester")
	assert.NoError(t, err)
	assert.Equal(t, "application/test", item.GetMonadType())
	assert.Equal(t, []byte("payload"), item.GetMonadValue())

	err = parsed.Verify(nil)
	assert.NoError(t, err)

	verifier, err := cose.NewVerifier(cose.AlgorithmES256, parsed.SigningCert.PublicKey)
	assert.NoError(t, err)
	err = parsed.Verify(verifier)
	assert.NoError(t, err)
}

func TestEvidenceMarshalV2UsesSignerPaths(t *testing.T) {
	evidence, err := NewEvidence(
		RATSDTokenVersionV2,
		WithSignerPaths(filepath.Join(testCertPath), filepath.Join(testKeyPath)),
	)
	assert.NoError(t, err)

	err = evidence.AddNonce([]byte("12345678"))
	assert.NoError(t, err)
	err = evidence.AddToken("test-attester", "application/test", []byte("payload"))
	assert.NoError(t, err)

	token, err := evidence.Marshal()
	assert.NoError(t, err)

	verifyTokenV2Signature(t, token, filepath.Join(testCertPath))
}

func TestEvidenceVerifyFailsWhenSignedPayloadIsTampered(t *testing.T) {
	evidence, err := NewEvidence(
		RATSDTokenVersionV2,
		WithSignerPaths(filepath.Join(testCertPath), filepath.Join(testKeyPath)),
	)
	assert.NoError(t, err)

	err = evidence.AddNonce([]byte("12345678"))
	assert.NoError(t, err)
	err = evidence.AddToken("test-attester", "application/test", []byte("payload"))
	assert.NoError(t, err)

	token, err := evidence.Marshal()
	assert.NoError(t, err)

	parsed := &Evidence{}
	err = parsed.Unmarshal(token)
	assert.NoError(t, err)

	parsed.message.Payload = []byte("tampered")

	err = parsed.Verify(nil)
	assert.ErrorIs(t, err, cose.ErrVerification)
}
