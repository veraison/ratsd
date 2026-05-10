// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package token

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
	cose "github.com/veraison/go-cose"
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
	cborTagEATClaims uint64 = 601
	eatClaimNonce    int    = 10
	eatClaimProfile  int    = 265
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

	signer, leafCert, intermediateCerts, err := loadSignerFromPaths(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	return signCollectionV2(collection, signer, leafCert, intermediateCerts)
}

func loadCertificateChain(path string) ([]*x509.Certificate, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate %q: %w", path, err)
	}

	var chain []*x509.Certificate
	rest := pemData
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			if len(bytes.TrimSpace(rest)) != 0 {
				return nil, fmt.Errorf("failed to parse certificate %q", path)
			}
			break
		}
		rest = remainder
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate from %q: %w", path, err)
			}
			chain = append(chain, cert)
		}
	}

	if len(chain) == 0 {
		return nil, fmt.Errorf("no certificate found in %q", path)
	}

	return chain, nil
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

func selectSigningAlgorithm(key crypto.Signer) (cose.Algorithm, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		switch k.Curve.Params().BitSize {
		case 256:
			return cose.AlgorithmES256, nil
		case 384:
			return cose.AlgorithmES384, nil
		case 521:
			return cose.AlgorithmES512, nil
		default:
			return 0, fmt.Errorf("unsupported ECDSA curve size %d", k.Curve.Params().BitSize)
		}
	case *rsa.PrivateKey:
		switch {
		case k.N.BitLen() >= 4096:
			return cose.AlgorithmPS512, nil
		case k.N.BitLen() >= 3072:
			return cose.AlgorithmPS384, nil
		case k.N.BitLen() >= 2048:
			return cose.AlgorithmPS256, nil
		default:
			return 0, fmt.Errorf("RSA key must be at least 2048 bits, got %d", k.N.BitLen())
		}
	default:
		return 0, fmt.Errorf("unsupported private key type %T", key)
	}
}

func loadSignerFromPaths(certPath, keyPath string) (cose.Signer, *x509.Certificate, []*x509.Certificate, error) {
	chain, err := loadCertificateChain(certPath)
	if err != nil {
		return nil, nil, nil, err
	}

	key, err := loadPrivateKey(keyPath)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := ensureKeyMatchesCertificate(key, chain[0]); err != nil {
		return nil, nil, nil, err
	}

	alg, err := selectSigningAlgorithm(key)
	if err != nil {
		return nil, nil, nil, err
	}

	signer, err := cose.NewSigner(alg, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create COSE signer: %w", err)
	}

	return signer, chain[0], chain[1:], nil
}

func signCollectionV2(collection *cmw.CMW, signer cose.Signer, signingCert *x509.Certificate, intermediateCerts []*x509.Certificate) ([]byte, error) {
	if collection == nil {
		return nil, errors.New("nil CMW collection")
	}
	if signer == nil {
		return nil, errors.New("nil COSE signer")
	}

	payload, err := collection.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize CMW collection as CBOR: %w", err)
	}

	msg := cose.NewSign1Message()
	msg.Payload = payload
	msg.Headers.Protected.SetAlgorithm(signer.Algorithm())

	if signingCert != nil {
		if len(intermediateCerts) == 0 {
			msg.Headers.Protected[cose.HeaderLabelX5Chain] = signingCert.Raw
		} else {
			chain := make([][]byte, 0, len(intermediateCerts)+1)
			chain = append(chain, signingCert.Raw)
			for _, cert := range intermediateCerts {
				chain = append(chain, cert.Raw)
			}
			msg.Headers.Protected[cose.HeaderLabelX5Chain] = chain
		}
	} else if len(intermediateCerts) > 0 {
		return nil, errors.New("intermediate certificates supplied but no signing certificate")
	}

	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("failed to sign CMW collection: %w", err)
	}

	token, err := msg.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize COSE_Sign1 token: %w", err)
	}

	return token, nil
}
