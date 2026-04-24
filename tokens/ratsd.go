// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/cmw"
)

const (
	RATSDTokenVersionLegacy = 1
	RATSDTokenVersionV2     = 2

	RATSDLegacyProfile = "tag:github.com,2024:veraison/ratsd"
	RATSDV2Profile     = "tag:github.com,2026:veraison/ratsd/v2"

	RATSDCollectionTypeLegacy = "tag:github.com,2025:veraison/ratsd/cmw"
	RATSDCollectionTypeV2     = "tag:github.com,2025:veraison/ratsd/cmw/v2"

	RATSDTokenMediaTypeV2  = "application/cmw+cbor; cmwct=\"" + RATSDV2Profile + "\""
	RATSDClaimsMediaTypeV2 = "application/eat-ucs+cbor; eat_profile=\"" + RATSDV2Profile + "\""
)

const (
	cborTagEATClaims  uint64 = 601
	cborTagCOSESign1  uint64 = 18
	coseHeaderAlg     int64  = 1
	coseHeaderX5Chain int64  = 33
	eatClaimNonce     int    = 10
	eatClaimProfile   int    = 265
)

// AddClaimsToCollectionV2 inserts the ratsd claims record required by token v2.
func AddClaimsToCollectionV2(collection *cmw.CMW, nonce []byte) error {
	if collection == nil {
		return errors.New("nil CMW collection")
	}
	if len(nonce) < 8 || len(nonce) > 64 {
		return fmt.Errorf("nonce size must be between 8 and 64 bytes for token version 2")
	}

	claims, err := cbor.Marshal(cbor.Tag{
		Number: cborTagEATClaims,
		Content: map[int]any{
			eatClaimProfile: RATSDV2Profile,
			eatClaimNonce:   nonce,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to serialize ratsd claims: %w", err)
	}

	if err := collection.AddCollectionItem("__ratsd", cmw.NewMonad(RATSDClaimsMediaTypeV2, claims)); err != nil {
		return fmt.Errorf("failed to add ratsd claims: %w", err)
	}

	return nil
}

// CreateTokenV2 signs the supplied v2 CMW collection as a COSE_Sign1 token.
func CreateTokenV2(collection *cmw.CMW, certPath, keyPath string) ([]byte, error) {
	if collection == nil {
		return nil, errors.New("nil CMW collection")
	}
	if certPath == "" || keyPath == "" {
		return nil, errors.New("token version 2 requires cert and cert-key configuration")
	}

	payload, err := collection.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize CMW collection as CBOR: %w", err)
	}

	x5chain, leafCert, err := loadCertificateChain(certPath)
	if err != nil {
		return nil, err
	}

	key, err := loadPrivateKey(keyPath)
	if err != nil {
		return nil, err
	}
	if err := ensureKeyMatchesCertificate(key, leafCert); err != nil {
		return nil, err
	}

	alg, hash, err := selectSigningAlgorithm(key)
	if err != nil {
		return nil, err
	}

	protected, err := cbor.Marshal(map[int64]any{
		coseHeaderAlg:     alg,
		coseHeaderX5Chain: x5chain,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to serialize protected headers: %w", err)
	}

	toBeSigned, err := cbor.Marshal([]any{
		"Signature1",
		protected,
		[]byte{},
		payload,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Sig_structure: %w", err)
	}

	signature, err := signCOSEPayload(key, hash, toBeSigned)
	if err != nil {
		return nil, err
	}

	return cbor.Marshal(cbor.Tag{
		Number: cborTagCOSESign1,
		Content: []any{
			protected,
			map[any]any{},
			payload,
			signature,
		},
	})
}

func loadCertificateChain(path string) (any, *x509.Certificate, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read certificate %q: %w", path, err)
	}

	var chain [][]byte
	rest := pemData
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			if len(bytes.TrimSpace(rest)) != 0 {
				return nil, nil, fmt.Errorf("failed to parse certificate %q", path)
			}
			break
		}
		rest = remainder
		if block.Type == "CERTIFICATE" {
			chain = append(chain, block.Bytes)
		}
	}

	if len(chain) == 0 {
		return nil, nil, fmt.Errorf("no certificate found in %q", path)
	}

	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse leaf certificate from %q: %w", path, err)
	}

	if len(chain) == 1 {
		return chain[0], leaf, nil
	}

	return chain, leaf, nil
}

func loadPrivateKey(path string) (crypto.Signer, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key %q: %w", path, err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse private key %q", path)
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key %q: %w", path, err)
		}
		return key, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA private key %q: %w", path, err)
		}
		return key, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key %q: %w", path, err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("unsupported PKCS#8 private key type %T in %q", key, path)
		}
		return signer, nil
	default:
		return nil, fmt.Errorf("unsupported private key PEM block %q in %q", block.Type, path)
	}
}

func ensureKeyMatchesCertificate(key crypto.Signer, cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("missing signing certificate")
	}

	keyPub, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return fmt.Errorf("failed to marshal signing public key: %w", err)
	}
	certPub, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal certificate public key: %w", err)
	}
	if !bytes.Equal(keyPub, certPub) {
		return errors.New("certificate and private key do not match")
	}

	return nil
}

func selectSigningAlgorithm(key crypto.Signer) (int64, crypto.Hash, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		switch k.Curve.Params().BitSize {
		case 256:
			return -7, crypto.SHA256, nil
		case 384:
			return -35, crypto.SHA384, nil
		case 521:
			return -36, crypto.SHA512, nil
		default:
			return 0, 0, fmt.Errorf("unsupported ECDSA curve size %d", k.Curve.Params().BitSize)
		}
	case *rsa.PrivateKey:
		switch {
		case k.N.BitLen() >= 4096:
			return -39, crypto.SHA512, nil
		case k.N.BitLen() >= 3072:
			return -38, crypto.SHA384, nil
		case k.N.BitLen() >= 2048:
			return -37, crypto.SHA256, nil
		default:
			return 0, 0, fmt.Errorf("RSA key must be at least 2048 bits, got %d", k.N.BitLen())
		}
	default:
		return 0, 0, fmt.Errorf("unsupported private key type %T", key)
	}
}

func signCOSEPayload(key crypto.Signer, hash crypto.Hash, payload []byte) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("hash %v is not available", hash)
	}

	hasher := hash.New()
	if _, err := hasher.Write(payload); err != nil {
		return nil, fmt.Errorf("failed to hash COSE payload: %w", err)
	}
	digest := hasher.Sum(nil)

	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, k, digest)
		if err != nil {
			return nil, fmt.Errorf("failed to sign token with ECDSA: %w", err)
		}
		size := (k.Curve.Params().BitSize + 7) / 8
		signature := make([]byte, size*2)
		r.FillBytes(signature[:size])
		s.FillBytes(signature[size:])
		return signature, nil
	case *rsa.PrivateKey:
		sig, err := rsa.SignPSS(rand.Reader, k, hash, digest, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       hash,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to sign token with RSA-PSS: %w", err)
		}
		return sig, nil
	default:
		return nil, fmt.Errorf("unsupported private key type %T", key)
	}
}
