// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package ratsdtokenv2

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/cmw"
	cose "github.com/veraison/go-cose"
)

func validEvidence() *Evidence {
	evidence := NewEvidence()

	if err := evidence.Claims.SetNonce([]byte("12345678")); err != nil {
		panic(err)
	}

	if err := evidence.Claims.SetNonceAdjustFn(NonceAdjustFunctionShake256); err != nil {
		panic(err)
	}

	if err := evidence.Claims.SetKeyandNonceSz("configfs-tsm", 32); err != nil {
		panic(err)
	}

	if err := evidence.SetToken(
		"configfs-tsm",
		"application/vnd.veraison.tsm-report+cbor",
		[]byte{0xa1, 0x67, 0x6f, 0x75, 0x74, 0x62, 0x6c, 0x6f, 0x62, 0x41, 0xff},
		cmw.Evidence,
	); err != nil {
		panic(err)
	}

	evidence.ProtectedHeaders.SetX5Chain([]byte{0xff})
	if err := evidence.SetSignature([]byte{0xee}); err != nil {
		panic(err)
	}

	return evidence
}

func assertEvidenceEquivalent(t *testing.T, expected, actual *Evidence) {
	t.Helper()

	assert.Equal(t, expected.ProtectedHeaders.GetX5Chain(), actual.ProtectedHeaders.GetX5Chain())
	assert.Equal(t, expected.Claims.GetEatProfile(), actual.Claims.GetEatProfile())
	assert.Equal(t, expected.Claims.GetEatNonce(), actual.Claims.GetEatNonce())
	assert.Equal(t, expected.Claims.GetNonceAdjustFn(), actual.Claims.GetNonceAdjustFn())
	assert.Equal(t, expected.Claims.GetNonceAdjustMap(), actual.Claims.GetNonceAdjustMap())
	assert.Equal(t, mustMarshalCMW(t, expected.Collection), mustMarshalCMW(t, actual.Collection))
	assert.Equal(t, expected.GetSignature(), actual.GetSignature())
}

func mustMarshalCMW(t *testing.T, collection cmw.CMW) []byte {
	t.Helper()

	encoded, err := collection.MarshalCBOR()
	require.NoError(t, err)
	return encoded
}

func testSignerVerifier(t *testing.T) (cose.Signer, cose.Verifier) {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, privateKey)
	require.NoError(t, err)

	verifier, err := cose.NewVerifier(cose.AlgorithmEdDSA, privateKey.Public())
	require.NoError(t, err)

	return signer, verifier
}

func TestNewEvidence(t *testing.T) {
	evidence := NewEvidence()

	assert.Equal(t, Profile, evidence.Claims.GetEatProfile())
	meta, err := evidence.Collection.GetCollectionMeta()
	require.NoError(t, err)
	assert.Empty(t, meta)
	assert.Empty(t, evidence.GetSignature())
}

func TestClaimsSetNonce(t *testing.T) {
	var claims Claims

	assert.NoError(t, claims.SetNonce([]byte("abcdefgh")))
	assert.Equal(t, []byte("abcdefgh"), claims.GetEatNonce())
}

func TestClaimsSetNonceFail(t *testing.T) {
	var claims Claims

	assert.EqualError(t, claims.SetNonce([]byte("short")), "a nonce must be between 8 and 64 bytes long; found 5")
	assert.Nil(t, claims.EatNonce)
}

func TestClaimsSetNonceAdjustFn(t *testing.T) {
	var claims Claims

	assert.NoError(t, claims.SetNonceAdjustFn(NonceAdjustFunctionShake128))
	assert.Equal(t, NonceAdjustFunctionShake128, claims.GetNonceAdjustFn())
}

func TestClaimsSetNonceAdjustFnFail(t *testing.T) {
	var claims Claims

	assert.EqualError(t, claims.SetNonceAdjustFn("sha-256"), `invalid claim "nonce_adjust_function": "sha-256"`)
	assert.Nil(t, claims.NonceAdjustFunction)
}

func TestClaimsSetKeyandNonceSz(t *testing.T) {
	var claims Claims

	assert.NoError(t, claims.SetKeyandNonceSz("configfs-tsm", 32))
	assert.Equal(t, map[string]uint{"configfs-tsm": 32}, claims.GetNonceAdjustMap())
	sz, ok := claims.GetKeyandNonceSz("configfs-tsm")
	assert.True(t, ok)
	assert.Equal(t, uint(32), sz)
}

func TestClaimsSetKeyandNonceSzFail(t *testing.T) {
	var claims Claims

	assert.EqualError(t, claims.SetKeyandNonceSz("", 32), `invalid claim "nonce_adjust_map": empty key`)
	assert.Nil(t, claims.NonceAdjustMap)
}

func TestEvidenceSetCollectionCopiesCMWCollection(t *testing.T) {
	collection := cmw.NewCollection(CMWCollectionType)
	require.NotNil(t, collection)
	require.NoError(t, collection.AddCollectionItem(
		"mock-tsm",
		cmw.NewMonad("application/octet-stream", []byte{0x01, 0x02}, cmw.Evidence),
	))

	evidence := validEvidence()
	require.NoError(t, evidence.SetCollection(*collection))

	require.NoError(t, collection.AddCollectionItem(
		"other",
		cmw.NewMonad("application/octet-stream", []byte{0x03}),
	))

	stored, err := evidence.GetCollection()
	require.NoError(t, err)
	_, err = stored.GetCollectionItem("other")
	assert.EqualError(t, err, `item not found for key "other"`)

	record, err := stored.GetCollectionItem("mock-tsm")
	require.NoError(t, err)
	assert.Equal(t, "application/octet-stream", record.GetMonadType())
	assert.Equal(t, []byte{0x01, 0x02}, record.GetMonadValue())
	assert.Equal(t, cmw.Indicator(cmw.Evidence), record.GetMonadIndicator())
}

func TestEvidenceSetTokenStoresCMWMonad(t *testing.T) {
	evidence := NewEvidence()
	token := []byte{0x01, 0x02}

	require.NoError(t, evidence.SetToken("mock-tsm", "application/octet-stream", token, cmw.Evidence))
	token[0] = 0xff

	record, err := evidence.Collection.GetCollectionItem("mock-tsm")
	require.NoError(t, err)
	assert.Equal(t, "application/octet-stream", record.GetMonadType())
	assert.Equal(t, []byte{0x01, 0x02}, record.GetMonadValue())
	assert.Equal(t, cmw.Indicator(cmw.Evidence), record.GetMonadIndicator())
}

func TestEvidenceSetTokenFail(t *testing.T) {
	evidence := NewEvidence()

	assert.EqualError(t,
		evidence.SetToken("__ratsd", "application/octet-stream", []byte{0x01}),
		`validation failed: invalid CMW collection key "__ratsd": reserved`,
	)
	assert.EqualError(t,
		evidence.SetToken("mock-tsm", "", []byte{0x01}),
		`validation failed: invalid CMW record at key "mock-tsm": missing mandatory CMW record type`,
	)
	assert.EqualError(t,
		evidence.SetToken("mock-tsm", "application/octet-stream", nil),
		`validation failed: invalid CMW record at key "mock-tsm": missing mandatory CMW record value`,
	)
}

func TestEvidenceSetCollectionFailReservedKey(t *testing.T) {
	collection := cmw.NewCollection(CMWCollectionType)
	require.NotNil(t, collection)
	require.NoError(t, collection.AddCollectionItem(
		"__ratsd",
		cmw.NewMonad("application/octet-stream", []byte{0x01}),
	))

	evidence := validEvidence()
	assert.EqualError(t, evidence.SetCollection(*collection), `validation failed: invalid CMW collection key "__ratsd": reserved`)
}

func TestEvidenceValidPass(t *testing.T) {
	assert.NoError(t, validEvidence().Valid())
}

func TestEvidenceSetClaimsPass(t *testing.T) {
	src := validEvidence()
	evidence := validEvidence()

	err := evidence.SetClaims(src.Claims)

	assert.NoError(t, err)
	assert.Equal(t, src.Claims.GetEatNonce(), evidence.Claims.GetEatNonce())
}

func TestEvidenceSetClaimsFail(t *testing.T) {
	evidence := validEvidence()
	invalid := evidence.Claims
	invalid.EatNonce = nil

	err := evidence.SetClaims(invalid)

	assert.EqualError(t, err, `validation failed: missing mandatory claim "eat_nonce"`)
	assert.Equal(t, []byte("12345678"), evidence.Claims.GetEatNonce())
}

func TestEvidenceGetClaimsReturnsCopy(t *testing.T) {
	evidence := validEvidence()

	claims, err := evidence.GetClaims()
	require.NoError(t, err)

	claims.EatNonce[0] = 'x'
	*claims.NonceAdjustFunction = NonceAdjustFunctionShake128
	claims.NonceAdjustMap["configfs-tsm"] = 64

	assert.Equal(t, []byte("12345678"), evidence.Claims.GetEatNonce())
	assert.Equal(t, NonceAdjustFunctionShake256, evidence.Claims.GetNonceAdjustFn())
	assert.Equal(t, map[string]uint{"configfs-tsm": 32}, evidence.Claims.GetNonceAdjustMap())
}

func TestEvidenceValidFailWrongProfile(t *testing.T) {
	evidence := validEvidence()
	evidence.Claims.EatProfile = "tag:github.com,2024:veraison/ratsd"

	assert.EqualError(t, evidence.Valid(), `invalid claim "eat_profile": expected "tag:github.com,2026:veraison/ratsd/v2"`)
}

func TestEvidenceValidFailNonceAdjustMapWithoutFunction(t *testing.T) {
	evidence := validEvidence()
	evidence.Claims.NonceAdjustFunction = nil

	assert.EqualError(t, evidence.Valid(), `missing mandatory claim "nonce_adjust_function"`)
}

func TestEvidenceValidFailNoCollectionRecords(t *testing.T) {
	evidence := validEvidence()
	emptyCollection := cmw.NewCollection(CMWCollectionType)
	require.NotNil(t, emptyCollection)
	evidence.Collection = *emptyCollection

	assert.EqualError(t, evidence.Valid(), "missing mandatory CMW collection record")
}

func TestProtectedHeadersX5ChainArrayRoundTrip(t *testing.T) {
	evidence := validEvidence()
	evidence.ProtectedHeaders.SetX5Chain([]byte{0x01}, []byte{0x02})

	encoded, err := evidence.ToCBOR()
	require.NoError(t, err)

	var decoded Evidence
	require.NoError(t, decoded.FromCBOR(encoded))

	assert.Equal(t, [][]byte{{0x01}, {0x02}}, decoded.ProtectedHeaders.GetX5Chain())
}

func TestEvidenceSignAndVerify(t *testing.T) {
	signer, verifier := testSignerVerifier(t)
	evidence := validEvidence()
	evidence.Signature = nil
	evidence.ProtectedHeaders.Algorithm = nil

	encoded, err := evidence.Sign(signer)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)
	assert.NotEmpty(t, evidence.GetSignature())
	alg, ok := evidence.ProtectedHeaders.GetAlgorithm()
	require.True(t, ok)
	assert.Equal(t, cose.AlgorithmEdDSA, alg)
	assert.NoError(t, evidence.Verify(verifier))

	var decoded Evidence
	require.NoError(t, decoded.FromCBOR(encoded))
	assert.NoError(t, decoded.Verify(verifier))
	decoded.Claims.EatNonce[0] = 'x'
	assert.Error(t, decoded.Verify(verifier))
}

func TestEvidenceSignFailNilSigner(t *testing.T) {
	evidence := validEvidence()

	encoded, err := evidence.Sign(nil)

	assert.EqualError(t, err, "nil signer")
	assert.Nil(t, encoded)
}

func TestEvidenceCBORShape(t *testing.T) {
	evidence := validEvidence()

	encoded, err := evidence.ToCBOR()
	require.NoError(t, err)

	var tag cbor.RawTag
	require.NoError(t, tag.UnmarshalCBOR(encoded))
	assert.Equal(t, uint64(coseSign1TagNumber), tag.Number)

	var coseItems []cbor.RawMessage
	require.NoError(t, decMode.Unmarshal(tag.Content, &coseItems))
	require.Len(t, coseItems, 4)

	var protectedBytes []byte
	require.NoError(t, decMode.Unmarshal(coseItems[0], &protectedBytes))
	var protected map[any]cbor.RawMessage
	require.NoError(t, decMode.Unmarshal(protectedBytes, &protected))
	require.Contains(t, protected, uint64(protectedHeaderLabelX5Chain))
	var x5chain []byte
	require.NoError(t, decMode.Unmarshal(protected[uint64(protectedHeaderLabelX5Chain)], &x5chain))
	assert.Equal(t, []byte{0xff}, x5chain)

	var unprotected map[any]cbor.RawMessage
	require.NoError(t, decMode.Unmarshal(coseItems[1], &unprotected))
	assert.Empty(t, unprotected)

	var payloadBytes []byte
	require.NoError(t, decMode.Unmarshal(coseItems[2], &payloadBytes))
	var payload map[string]cbor.RawMessage
	require.NoError(t, decMode.Unmarshal(payloadBytes, &payload))

	var collectionType string
	require.NoError(t, decMode.Unmarshal(payload[cmwCollectionTypeKey], &collectionType))
	assert.Equal(t, CMWCollectionType, collectionType)

	var ratsdRecord []cbor.RawMessage
	require.NoError(t, decMode.Unmarshal(payload[ratsdClaimsKey], &ratsdRecord))
	require.Len(t, ratsdRecord, 2)

	var mediaType string
	require.NoError(t, decMode.Unmarshal(ratsdRecord[0], &mediaType))
	assert.Equal(t, ClaimsMediaType, mediaType)

	var claimsBytes []byte
	require.NoError(t, decMode.Unmarshal(ratsdRecord[1], &claimsBytes))
	var claimsTag cbor.RawTag
	require.NoError(t, claimsTag.UnmarshalCBOR(claimsBytes))
	assert.Equal(t, uint64(claimsTagNumber), claimsTag.Number)

	var claims map[any]cbor.RawMessage
	require.NoError(t, decMode.Unmarshal(claimsTag.Content, &claims))
	require.Contains(t, claims, uint64(claimLabelEatProfile))
	require.Contains(t, claims, uint64(claimLabelEatNonce))
	require.Contains(t, claims, int64(claimLabelNonceAdjustFunction))
	require.Contains(t, claims, int64(claimLabelNonceAdjustMap))

	var profile string
	require.NoError(t, decMode.Unmarshal(claims[uint64(claimLabelEatProfile)], &profile))
	assert.Equal(t, Profile, profile)

	var nonce []byte
	require.NoError(t, decMode.Unmarshal(claims[uint64(claimLabelEatNonce)], &nonce))
	assert.Equal(t, []byte("12345678"), nonce)

	var tsmRecord cmw.CMW
	require.NoError(t, tsmRecord.UnmarshalCBOR(payload["configfs-tsm"]))
	assert.Equal(t, "application/vnd.veraison.tsm-report+cbor", tsmRecord.GetMonadType())
	assert.Equal(t, cmw.Indicator(cmw.Evidence), tsmRecord.GetMonadIndicator())

	var signature []byte
	require.NoError(t, decMode.Unmarshal(coseItems[3], &signature))
	assert.Equal(t, []byte{0xee}, signature)
}

func TestEvidenceCBORSerDesPass(t *testing.T) {
	evidence := validEvidence()

	encoded, err := evidence.ToCBOR()
	require.NoError(t, err)

	var decoded Evidence
	require.NoError(t, decoded.FromCBOR(encoded))
	assertEvidenceEquivalent(t, evidence, &decoded)
}

func TestEvidenceCBORSerDesRejectsWrongTag(t *testing.T) {
	wrongTagBytes, err := cbor.RawTag{
		Number:  19,
		Content: []byte{0x80},
	}.MarshalCBOR()
	require.NoError(t, err)

	var decoded Evidence
	assert.EqualError(t, decoded.FromCBOR(wrongTagBytes), "CBOR decoding failed: cbor: invalid COSE_Sign1_Tagged object")
}
