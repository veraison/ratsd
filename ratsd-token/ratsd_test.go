// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/veraison/cmw"
)

type testCOSESign1Message struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[any]any
	Payload     []byte
	Signature   []byte
}

func TestAddClaimsToCollectionV2_rejectsInvalidNonce(t *testing.T) {
	collection := cmw.NewCollection(RATSDCollectionTypeV2)
	err := AddClaimsToCollectionV2(collection, []byte("short"))
	assert.EqualError(t, err, "nonce size must be between 8 and 64 bytes for token version 2")
}

func TestCreateTokenV2(t *testing.T) {
	collection := cmw.NewCollection(RATSDCollectionTypeV2)
	err := collection.AddCollectionItem("test-attester", cmw.NewMonad("application/test", []byte("payload")))
	assert.NoError(t, err)

	nonce := []byte("12345678")
	err = AddClaimsToCollectionV2(collection, nonce)
	assert.NoError(t, err)

	token, err := CreateTokenV2(
		collection,
		filepath.Join("..", "ratsd.crt"),
		filepath.Join("..", "ratsd.key"),
	)
	assert.NoError(t, err)

	msg := decodeTokenV2(t, token)
	assert.NotEmpty(t, msg.Signature)
	assert.Empty(t, msg.Unprotected)

	var protected map[int64]any
	err = cbor.Unmarshal(msg.Protected, &protected)
	assert.NoError(t, err)
	assert.Equal(t, int64(-7), protected[1])

	x5chain, ok := protected[33].([]byte)
	assert.True(t, ok)
	assert.NotEmpty(t, x5chain)

	decoded := &cmw.CMW{}
	err = decoded.UnmarshalCBOR(msg.Payload)
	assert.NoError(t, err)

	claimsRecord, err := decoded.GetCollectionItem("__ratsd")
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

	verifyTokenV2Signature(t, token, filepath.Join("..", "ratsd.crt"))
}

func decodeTokenV2(t *testing.T, data []byte) *testCOSESign1Message {
	t.Helper()

	var tag cbor.Tag
	err := cbor.Unmarshal(data, &tag)
	assert.NoError(t, err)
	assert.Equal(t, uint64(18), tag.Number)

	content, err := cbor.Marshal(tag.Content)
	assert.NoError(t, err)

	msg := &testCOSESign1Message{}
	err = cbor.Unmarshal(content, msg)
	assert.NoError(t, err)

	return msg
}

func verifyTokenV2Signature(t *testing.T, data []byte, certPath string) {
	t.Helper()

	msg := decodeTokenV2(t, data)

	var protected map[int64]any
	err := cbor.Unmarshal(msg.Protected, &protected)
	assert.NoError(t, err)

	toBeSigned, err := cbor.Marshal([]any{
		"Signature1",
		msg.Protected,
		[]byte{},
		msg.Payload,
	})
	assert.NoError(t, err)

	cert := loadLeafCertificate(t, certPath)

	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		hash := crypto.SHA256
		hasher := hash.New()
		_, err = hasher.Write(toBeSigned)
		assert.NoError(t, err)
		digest := hasher.Sum(nil)

		size := len(msg.Signature) / 2
		r := new(big.Int).SetBytes(msg.Signature[:size])
		s := new(big.Int).SetBytes(msg.Signature[size:])
		assert.True(t, ecdsa.Verify(pub, digest, r, s))
	case *rsa.PublicKey:
		hash := crypto.SHA256
		hasher := hash.New()
		_, err = hasher.Write(toBeSigned)
		assert.NoError(t, err)
		digest := hasher.Sum(nil)
		err = rsa.VerifyPSS(pub, hash, digest, msg.Signature, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       hash,
		})
		assert.NoError(t, err)
	default:
		t.Fatalf("unexpected certificate key type %T", cert.PublicKey)
	}
}

func loadLeafCertificate(t *testing.T, path string) *x509.Certificate {
	t.Helper()

	pemData, err := os.ReadFile(path)
	assert.NoError(t, err)

	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatalf("failed to parse certificate %s", path)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	assert.NoError(t, err)
	return cert
}
