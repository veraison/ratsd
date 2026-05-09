// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/cmw"
	cose "github.com/veraison/go-cose"
)

const claimsKeyRATSD = "__ratsd"

// Evidence builds and inspects RATSD attestation tokens independently of the HTTP API.
type Evidence struct {
	tokenVersion int
	claims       map[int]any
	collection   *cmw.CMW
	certPath     string
	certKeyPath  string

	SigningCert       *x509.Certificate
	IntermediateCerts []*x509.Certificate
	message           *cose.Sign1Message
}

// EvidenceOption customizes Evidence construction.
type EvidenceOption func(*Evidence)

// WithSignerPaths configures the certificate and private key used for token v2.
func WithSignerPaths(certPath, certKeyPath string) EvidenceOption {
	return func(e *Evidence) {
		e.certPath = certPath
		e.certKeyPath = certKeyPath
	}
}

// NewEvidence creates an attestation token builder for the requested token version.
func NewEvidence(tokenVersion int, options ...EvidenceOption) (*Evidence, error) {
	if tokenVersion != RATSDTokenVersionLegacy && tokenVersion != RATSDTokenVersionV2 {
		return nil, fmt.Errorf("unsupported token version %d", tokenVersion)
	}

	collectionType := RATSDCollectionTypeLegacy
	claims := make(map[int]any)
	if tokenVersion == RATSDTokenVersionV2 {
		collectionType = RATSDCollectionTypeV2
		claims[eatClaimProfile] = RATSDV2Profile
	}

	evidence := &Evidence{
		tokenVersion: tokenVersion,
		claims:       claims,
		collection:   cmw.NewCollection(collectionType),
	}

	for _, option := range options {
		option(evidence)
	}

	return evidence, nil
}

// MediaType returns the serialized evidence media type for the configured token version.
func (e *Evidence) MediaType() string {
	return ResponseMediaType(e.tokenVersion)
}

// Collection exposes the underlying CMW collection for inspection.
func (e *Evidence) Collection() *cmw.CMW {
	return e.collection
}

// Claims returns a copy of the evidence claims map.
func (e *Evidence) Claims() map[int]any {
	claims := make(map[int]any, len(e.claims))
	for key, value := range e.claims {
		switch typed := value.(type) {
		case []byte:
			claims[key] = append([]byte(nil), typed...)
		default:
			claims[key] = typed
		}
	}
	return claims
}

// SetClaim sets a claim that will be embedded in the evidence.
func (e *Evidence) SetClaim(key int, value any) {
	if e.claims == nil {
		e.claims = make(map[int]any)
	}
	switch typed := value.(type) {
	case []byte:
		e.claims[key] = append([]byte(nil), typed...)
	default:
		e.claims[key] = value
	}
}

// AddNonce stores the nonce that will be embedded in the serialized evidence.
func (e *Evidence) AddNonce(nonce []byte) error {
	if len(nonce) == 0 {
		return errors.New("missing nonce")
	}
	if e.tokenVersion == RATSDTokenVersionV2 && (len(nonce) < 8 || len(nonce) > 64) {
		return fmt.Errorf("nonce size must be between 8 and 64 bytes for token version 2")
	}

	e.SetClaim(eatClaimNonce, nonce)
	return nil
}

// AddToken inserts a sub-attester token into the CMW collection.
func (e *Evidence) AddToken(key, mediaType string, token []byte) error {
	if e.collection == nil {
		return errors.New("missing CMW collection")
	}
	if err := e.collection.AddCollectionItem(key, cmw.NewMonad(mediaType, token)); err != nil {
		return fmt.Errorf("failed to add CMW item for %s: %w", key, err)
	}

	return nil
}

// AddSigningCert adds a DER-encoded X.509 certificate to the COSE x5chain header.
func (e *Evidence) AddSigningCert(der []byte) error {
	if len(der) == 0 {
		return errors.New("nil signing cert")
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("invalid signing certificate: %w", err)
	}

	e.SigningCert = cert
	return nil
}

// AddIntermediateCerts adds concatenated DER-encoded X.509 certificates to the COSE x5chain header.
func (e *Evidence) AddIntermediateCerts(der []byte) error {
	if len(der) == 0 {
		return errors.New("nil or empty intermediate certs")
	}

	certs, err := x509.ParseCertificates(der)
	if err != nil {
		return fmt.Errorf("invalid intermediate certificates: %w", err)
	}
	if len(certs) == 0 {
		return errors.New("no certificates found in intermediate cert data")
	}

	e.IntermediateCerts = certs
	return nil
}

// Valid checks whether the builder has enough information to serialize an evidence payload.
func (e *Evidence) Valid() error {
	if e == nil {
		return errors.New("nil evidence")
	}
	if e.collection == nil {
		return errors.New("missing CMW collection")
	}
	if e.collection.GetKind() != cmw.KindCollection {
		return fmt.Errorf("want collection, got %q", e.collection.GetKind())
	}
	if _, err := e.collection.MarshalCBOR(); err != nil {
		return fmt.Errorf("invalid CMW collection: %w", err)
	}

	nonce, err := e.nonce()
	if err != nil {
		return err
	}
	if e.tokenVersion == RATSDTokenVersionV2 {
		profile, ok := e.claims[eatClaimProfile].(string)
		if !ok || profile != RATSDV2Profile {
			return errors.New("missing or invalid token version 2 profile claim")
		}
		if len(nonce) < 8 || len(nonce) > 64 {
			return fmt.Errorf("nonce size must be between 8 and 64 bytes for token version 2")
		}
	}

	return nil
}

// MarshalCollection serializes the unsigned evidence collection as CBOR.
func (e *Evidence) MarshalCollection() ([]byte, error) {
	if err := e.Valid(); err != nil {
		return nil, err
	}

	if e.tokenVersion == RATSDTokenVersionV2 {
		collection, err := e.buildSignedCollection()
		if err != nil {
			return nil, err
		}
		return collection.MarshalCBOR()
	}

	return e.collection.MarshalCBOR()
}

// Sign signs the evidence collection as a COSE_Sign1 token using a go-cose signer.
func (e *Evidence) Sign(signer cose.Signer) ([]byte, error) {
	if e.tokenVersion != RATSDTokenVersionV2 {
		return nil, errors.New("sign is only supported for token version 2")
	}
	if signer == nil {
		return nil, errors.New("nil COSE signer")
	}
	if err := e.ensureCertificateChainLoaded(); err != nil {
		return nil, err
	}

	collection, err := e.buildSignedCollection()
	if err != nil {
		return nil, err
	}

	token, err := signCollectionV2(collection, signer, e.SigningCert, e.IntermediateCerts)
	if err != nil {
		return nil, err
	}

	msg := cose.NewSign1Message()
	if err := msg.UnmarshalCBOR(token); err != nil {
		return nil, fmt.Errorf("failed to decode generated COSE_Sign1 token: %w", err)
	}
	e.message = msg

	return token, nil
}

// Marshal serializes the evidence token in the configured wire format.
func (e *Evidence) Marshal() ([]byte, error) {
	if err := e.Valid(); err != nil {
		return nil, err
	}

	switch e.tokenVersion {
	case RATSDTokenVersionV2:
		if e.certPath == "" || e.certKeyPath == "" {
			return nil, errors.New("token version 2 requires Sign(signer) or signer path configuration")
		}
		signer, signingCert, intermediateCerts, err := loadSignerFromPaths(e.certPath, e.certKeyPath)
		if err != nil {
			return nil, err
		}
		if e.SigningCert == nil {
			e.SigningCert = signingCert
			e.IntermediateCerts = intermediateCerts
		}
		return e.Sign(signer)
	case RATSDTokenVersionLegacy:
		return e.marshalLegacy()
	default:
		return nil, fmt.Errorf("unsupported token version %d", e.tokenVersion)
	}
}

// Unmarshal decodes a serialized evidence token into the Evidence structure.
func (e *Evidence) Unmarshal(data []byte) error {
	if e == nil {
		return errors.New("nil evidence")
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return errors.New("empty evidence token")
	}

	if trimmed[0] == '{' {
		return e.unmarshalLegacy(trimmed)
	}

	return e.unmarshalV2(trimmed)
}

// Verify verifies the signed token against the current CMW collection state.
func (e *Evidence) Verify(verifier cose.Verifier) error {
	if e == nil {
		return errors.New("nil evidence")
	}
	if e.tokenVersion != RATSDTokenVersionV2 {
		return errors.New("verify is only supported for token version 2")
	}
	if e.message == nil {
		return errors.New("missing signed token")
	}

	if verifier == nil {
		if e.SigningCert == nil {
			return errors.New("missing verifier and embedded signing certificate")
		}
		alg, err := e.message.Headers.Protected.Algorithm()
		if err != nil {
			return fmt.Errorf("failed to determine COSE algorithm: %w", err)
		}
		verifier, err = cose.NewVerifier(alg, e.SigningCert.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to create verifier from embedded signing certificate: %w", err)
		}
	}

	return e.message.Verify(nil, verifier)
}

// ResponseMediaType returns the media type for the requested token version.
func ResponseMediaType(tokenVersion int) string {
	switch tokenVersion {
	case RATSDTokenVersionV2:
		return RATSDTokenMediaTypeV2
	default:
		return fmt.Sprintf(`application/eat-ucs+json; eat_profile=%q`, RATSDLegacyProfile)
	}
}

func (e *Evidence) marshalLegacy() ([]byte, error) {
	nonce, err := e.nonce()
	if err != nil {
		return nil, err
	}

	serialized, err := e.collection.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize CMW collection: %w", err)
	}

	token, err := json.Marshal(map[string]any{
		"eat_profile": RATSDLegacyProfile,
		"eat_nonce":   base64.RawURLEncoding.EncodeToString(nonce),
		"cmw":         serialized,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to serialize legacy token: %w", err)
	}

	return token, nil
}

func (e *Evidence) buildSignedCollection() (*cmw.CMW, error) {
	collection, err := cloneCollection(e.collection)
	if err != nil {
		return nil, err
	}

	claimsRecord, err := e.marshalClaimsRecordV2()
	if err != nil {
		return nil, err
	}

	if err := collection.AddCollectionItem(claimsKeyRATSD, cmw.NewMonad(RATSDClaimsMediaTypeV2, claimsRecord)); err != nil {
		return nil, fmt.Errorf("failed to add ratsd claims: %w", err)
	}

	return collection, nil
}

func (e *Evidence) marshalClaimsRecordV2() ([]byte, error) {
	if e.tokenVersion != RATSDTokenVersionV2 {
		return nil, errors.New("claims record is only supported for token version 2")
	}

	claims := e.Claims()
	profile, ok := claims[eatClaimProfile].(string)
	if !ok || profile != RATSDV2Profile {
		return nil, errors.New("missing or invalid token version 2 profile claim")
	}

	nonceValue, ok := claims[eatClaimNonce]
	if !ok {
		return nil, errors.New("missing nonce")
	}
	nonce, ok := nonceValue.([]byte)
	if !ok {
		return nil, fmt.Errorf("nonce claim must be []byte, got %T", nonceValue)
	}
	if len(nonce) < 8 || len(nonce) > 64 {
		return nil, fmt.Errorf("nonce size must be between 8 and 64 bytes for token version 2")
	}

	claims[eatClaimNonce] = append([]byte(nil), nonce...)
	record, err := cbor.Marshal(cbor.Tag{
		Number:  cborTagEATClaims,
		Content: claims,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ratsd claims: %w", err)
	}

	return record, nil
}

func (e *Evidence) ensureCertificateChainLoaded() error {
	if e.SigningCert != nil {
		return nil
	}
	if len(e.IntermediateCerts) > 0 {
		return errors.New("intermediate certificates supplied but no signing certificate")
	}
	if e.certPath == "" {
		return nil
	}

	chain, err := loadCertificateChain(e.certPath)
	if err != nil {
		return err
	}
	e.SigningCert = chain[0]
	e.IntermediateCerts = chain[1:]
	return nil
}

func (e *Evidence) nonce() ([]byte, error) {
	value, ok := e.claims[eatClaimNonce]
	if !ok {
		return nil, errors.New("missing nonce")
	}

	nonce, ok := value.([]byte)
	if !ok {
		return nil, fmt.Errorf("nonce claim must be []byte, got %T", value)
	}

	return append([]byte(nil), nonce...), nil
}

func (e *Evidence) unmarshalLegacy(data []byte) error {
	var wire struct {
		Profile string `json:"eat_profile"`
		Nonce   string `json:"eat_nonce"`
		CMW     string `json:"cmw"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return fmt.Errorf("failed to decode legacy token: %w", err)
	}

	nonce, err := base64.RawURLEncoding.DecodeString(wire.Nonce)
	if err != nil {
		return fmt.Errorf("failed to decode legacy nonce: %w", err)
	}
	collectionJSON, err := base64.StdEncoding.DecodeString(wire.CMW)
	if err != nil {
		return fmt.Errorf("failed to decode legacy CMW payload: %w", err)
	}

	collection := &cmw.CMW{}
	if err := collection.UnmarshalJSON(collectionJSON); err != nil {
		return fmt.Errorf("failed to decode legacy CMW payload: %w", err)
	}

	e.tokenVersion = RATSDTokenVersionLegacy
	e.claims = map[int]any{
		eatClaimNonce: nonce,
	}
	e.collection = collection
	e.message = nil
	e.SigningCert = nil
	e.IntermediateCerts = nil

	return nil
}

func (e *Evidence) unmarshalV2(data []byte) error {
	msg := cose.NewSign1Message()
	if err := msg.UnmarshalCBOR(data); err != nil {
		return fmt.Errorf("failed to decode COSE_Sign1 token: %w", err)
	}

	collection := &cmw.CMW{}
	if err := collection.UnmarshalCBOR(msg.Payload); err != nil {
		return fmt.Errorf("failed to decode signed CMW collection: %w", err)
	}

	claims, err := extractClaimsFromCollection(collection)
	if err != nil {
		return err
	}
	stripped, err := stripClaimsItem(collection)
	if err != nil {
		return err
	}

	signingCert, intermediateCerts, err := parseCertificateChainHeader(msg.Headers.Protected[cose.HeaderLabelX5Chain])
	if err != nil {
		return err
	}

	e.tokenVersion = RATSDTokenVersionV2
	e.claims = claims
	e.collection = stripped
	e.message = msg
	e.SigningCert = signingCert
	e.IntermediateCerts = intermediateCerts

	return nil
}

func extractClaimsFromCollection(collection *cmw.CMW) (map[int]any, error) {
	claimsRecord, err := collection.GetCollectionItem(claimsKeyRATSD)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve ratsd claims: %w", err)
	}
	if claimsRecord.GetMonadType() != RATSDClaimsMediaTypeV2 {
		return nil, fmt.Errorf("unexpected ratsd claims media type %q", claimsRecord.GetMonadType())
	}

	var claimsTag cbor.Tag
	if err := cbor.Unmarshal(claimsRecord.GetMonadValue(), &claimsTag); err != nil {
		return nil, fmt.Errorf("failed to decode ratsd claims: %w", err)
	}
	if claimsTag.Number != cborTagEATClaims {
		return nil, fmt.Errorf("unexpected ratsd claims CBOR tag %d", claimsTag.Number)
	}

	claimsBytes, err := cbor.Marshal(claimsTag.Content)
	if err != nil {
		return nil, fmt.Errorf("failed to normalize ratsd claims: %w", err)
	}

	var claims map[int]any
	if err := cbor.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to decode ratsd claims map: %w", err)
	}

	return claims, nil
}

func stripClaimsItem(collection *cmw.CMW) (*cmw.CMW, error) {
	collectionType, err := collection.GetCollectionType()
	if err != nil {
		return nil, fmt.Errorf("failed to determine collection type: %w", err)
	}

	stripped := cmw.NewCollection(collectionType)
	if stripped == nil {
		return nil, errors.New("failed to initialize CMW collection")
	}

	meta, err := collection.GetCollectionMeta()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate collection items: %w", err)
	}

	for _, entry := range meta {
		if key, ok := entry.Key.(string); ok && key == claimsKeyRATSD {
			continue
		}

		node, err := collection.GetCollectionItem(entry.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve collection item %v: %w", entry.Key, err)
		}
		cloned, err := cloneNode(node)
		if err != nil {
			return nil, err
		}
		if err := stripped.AddCollectionItem(entry.Key, cloned); err != nil {
			return nil, fmt.Errorf("failed to clone collection item %v: %w", entry.Key, err)
		}
	}

	return stripped, nil
}

func cloneNode(node *cmw.CMW) (*cmw.CMW, error) {
	serialized, err := node.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize CMW node: %w", err)
	}

	cloned := &cmw.CMW{}
	if err := cloned.UnmarshalCBOR(serialized); err != nil {
		return nil, fmt.Errorf("failed to clone CMW node: %w", err)
	}

	return cloned, nil
}

func parseCertificateChainHeader(value any) (*x509.Certificate, []*x509.Certificate, error) {
	if value == nil {
		return nil, nil, nil
	}

	switch typed := value.(type) {
	case []byte:
		cert, err := x509.ParseCertificate(typed)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse x5chain leaf certificate: %w", err)
		}
		return cert, nil, nil
	case [][]byte:
		return parseRawCertificateChain(typed)
	case []any:
		rawChain := make([][]byte, 0, len(typed))
		for _, item := range typed {
			raw, ok := item.([]byte)
			if !ok {
				return nil, nil, fmt.Errorf("unexpected x5chain element type %T", item)
			}
			rawChain = append(rawChain, raw)
		}
		return parseRawCertificateChain(rawChain)
	default:
		return nil, nil, fmt.Errorf("unexpected x5chain header type %T", value)
	}
}

func parseRawCertificateChain(rawChain [][]byte) (*x509.Certificate, []*x509.Certificate, error) {
	if len(rawChain) == 0 {
		return nil, nil, errors.New("empty x5chain header")
	}

	parsed := make([]*x509.Certificate, 0, len(rawChain))
	for _, raw := range rawChain {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse x5chain certificate: %w", err)
		}
		parsed = append(parsed, cert)
	}

	return parsed[0], parsed[1:], nil
}

func cloneCollection(collection *cmw.CMW) (*cmw.CMW, error) {
	serialized, err := collection.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize CMW collection as CBOR: %w", err)
	}

	cloned := &cmw.CMW{}
	if err := cloned.UnmarshalCBOR(serialized); err != nil {
		return nil, fmt.Errorf("failed to clone CMW collection: %w", err)
	}

	return cloned, nil
}
