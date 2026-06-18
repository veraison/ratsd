// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
package ratsdtokenv2

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/cmw"
	"github.com/veraison/eat"
	cose "github.com/veraison/go-cose"
)

const (
	Profile           = "tag:github.com,2026:veraison/ratsd/v2"
	ClaimsMediaType   = "application/eat-ucs+cbor; eat_profile=\"" + Profile + "\""
	CMWCollectionType = "tag:github.com,2025:veraison/ratsd/cmw/v2"

	NonceAdjustFunctionShake128 = "shake-128"
	NonceAdjustFunctionShake256 = "shake-256"

	coseSign1TagNumber = cose.CBORTagSign1Message
	claimsTagNumber    = 601

	cmwCollectionTypeKey = "__cmwc_t"
	ratsdClaimsKey       = "__ratsd"

	claimLabelEatProfile          = 265
	claimLabelEatNonce            = 10
	claimLabelNonceAdjustFunction = -65537
	claimLabelNonceAdjustMap      = -65538

	protectedHeaderLabelX5Chain = cose.HeaderLabelX5Chain
)

var (
	encMode = mustEncMode()
	decMode = mustDecMode()

	errNilEvidence                = errors.New("nil evidence")
	errNilClaims                  = errors.New("nil claims")
	errEmptyNonceAdjustFunction   = errors.New(`invalid claim "nonce_adjust_function": empty value`)
	errEmptyNonceAdjustMapKey     = errors.New(`invalid claim "nonce_adjust_map": empty key`)
	errEmptyCollectionKey         = errors.New("invalid CMW collection key: empty value")
	errMissingEatProfile          = errors.New(`missing mandatory claim "eat_profile"`)
	errMissingEatNonce            = errors.New(`missing mandatory claim "eat_nonce"`)
	errMissingNonceAdjustFunction = errors.New(`missing mandatory claim "nonce_adjust_function"`)
	errMissingCMWRecordValue      = errors.New("missing mandatory CMW record value")
	errMissingCollectionRecord    = errors.New("missing mandatory CMW collection record")
	errMissingCollectionType      = errors.New(`missing mandatory CMW collection field "__cmwc_t"`)
	errMissingRATSDClaimsRecord   = errors.New(`missing mandatory CMW collection field "__ratsd"`)
)

func mustEncMode() cbor.EncMode {
	mode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(fmt.Sprintf("CBOR encoder initialization failed: %v", err))
	}

	return mode
}

func mustDecMode() cbor.DecMode {
	mode, err := cbor.DecOptions{}.DecMode()
	if err != nil {
		panic(fmt.Sprintf("CBOR decoder initialization failed: %v", err))
	}

	return mode
}

// Evidence exposes a RATSD v2 token as the COSE_Sign1 envelope defined in
// docs/ratsd-token.cddl.
type Evidence struct {
	ProtectedHeaders ProtectedHeaders
	Claims           Claims
	Collection       cmw.CMW
	Signature        []byte
}

// ProtectedHeaders contains the protected COSE header map.
type ProtectedHeaders struct {
	Algorithm *cose.Algorithm
	X5Chain   [][]byte
}

// Claims contains the tagged EAT claims embedded in the RATSD CMW collection.
type Claims struct {
	EatProfile          string
	EatNonce            []byte
	NonceAdjustFunction *string
	NonceAdjustMap      map[string]uint
}

// NewEvidence returns an Evidence with the RATSD v2 EAT profile preset.
func NewEvidence() *Evidence {
	collection := cmw.NewCollection(CMWCollectionType)
	if collection == nil {
		panic(fmt.Sprintf("invalid RATSD CMW collection type constant: %s", CMWCollectionType))
	}

	return &Evidence{
		Claims: Claims{
			EatProfile: Profile,
		},
		Collection: *collection,
		Signature:  []byte{},
	}
}

// SetClaims attaches the supplied claims to the Evidence instance.
// Only successfully validated claims are allowed to be set.
func (e *Evidence) SetClaims(c Claims) error {
	if e == nil {
		return errNilEvidence
	}

	if err := c.Valid(); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	e.Claims = cloneClaims(c)
	return nil
}

// GetClaims returns a copy of the stored claims after validating the evidence.
func (e Evidence) GetClaims() (Claims, error) {
	if err := e.Valid(); err != nil {
		return Claims{}, fmt.Errorf("validation failed: %w", err)
	}

	return cloneClaims(e.Claims), nil
}

// SetCollection attaches the supplied CMW collection to the Evidence instance.
// Most callers should use SetToken to add token bytes and media types directly.
// This method is intended for callers that already have a complete CMW
// collection, for example after decoding an existing token. The collection must
// contain only caller-supplied CMW records; the reserved "__ratsd" claims record
// is injected during token serialization.
func (e *Evidence) SetCollection(c cmw.CMW) error {
	if e == nil {
		return errNilEvidence
	}

	if err := validateUserCollection(c); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	clone, err := cloneCMW(c)
	if err != nil {
		return fmt.Errorf("collection copy failed: %w", err)
	}

	e.Collection = clone
	return nil
}

// GetCollection returns a copy of the stored collection after validation.
func (e Evidence) GetCollection() (cmw.CMW, error) {
	if err := e.Valid(); err != nil {
		return cmw.CMW{}, fmt.Errorf("validation failed: %w", err)
	}

	clone, err := cloneCMW(e.Collection)
	if err != nil {
		return cmw.CMW{}, fmt.Errorf("collection copy failed: %w", err)
	}

	return clone, nil
}

// SetToken stores caller-supplied token bytes as a CMW monad in the Evidence
// collection.
func (e *Evidence) SetToken(key string, mediaType string, token []byte, indicators ...cmw.Indicator) error {
	if e == nil {
		return errNilEvidence
	}

	if err := validateCollectionForToken(e.Collection); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	if err := validateCollectionKey(key); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	record := cmw.NewMonad(mediaType, cloneBytes(token), indicators...)
	if err := validateCMWRecord(key, *record); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	if err := e.Collection.AddCollectionItem(key, record); err != nil {
		return fmt.Errorf("adding CMW record at key %q: %w", key, err)
	}

	return nil
}

// SetSignature stores the COSE_Sign1 signature bytes.
func (e *Evidence) SetSignature(signature []byte) error {
	if e == nil {
		return errNilEvidence
	}

	e.Signature = bytesOrEmpty(signature)
	return nil
}

// GetSignature returns a copy of the COSE_Sign1 signature bytes.
func (e Evidence) GetSignature() []byte {
	return bytesOrEmpty(e.Signature)
}

// SetAlgorithm stores the COSE signing algorithm protected header.
func (h *ProtectedHeaders) SetAlgorithm(alg cose.Algorithm) {
	h.Algorithm = &alg
}

// GetAlgorithm returns the COSE signing algorithm protected header.
func (h ProtectedHeaders) GetAlgorithm() (cose.Algorithm, bool) {
	if h.Algorithm == nil {
		return 0, false
	}

	return *h.Algorithm, true
}

// SetX5Chain stores the x5chain protected header. A single certificate is
// encoded as bytes, while two or more certificates are encoded as an array.
func (h *ProtectedHeaders) SetX5Chain(certs ...[]byte) {
	h.X5Chain = cloneByteSlices(certs)
}

// GetX5Chain returns a copy of the x5chain protected header.
func (h ProtectedHeaders) GetX5Chain() [][]byte {
	return cloneByteSlices(h.X5Chain)
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

// Valid checks whether the Evidence matches the RATSD v2 token shape.
func (e *Evidence) Valid() error {
	if e == nil {
		return errNilEvidence
	}

	if err := e.ProtectedHeaders.Valid(); err != nil {
		return err
	}

	if err := e.Claims.Valid(); err != nil {
		return err
	}

	if err := validateUserCollection(e.Collection); err != nil {
		return err
	}

	return nil
}

// Valid checks whether the protected headers match the RATSD v2 token shape.
func (h ProtectedHeaders) Valid() error {
	if len(h.X5Chain) == 0 {
		return nil
	}

	if len(h.X5Chain) == 1 {
		return nil
	}

	for i, cert := range h.X5Chain {
		if cert == nil {
			return fmt.Errorf(`invalid protected header "x5chain": nil certificate at index %d`, i)
		}
	}

	return nil
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

// ToCBOR encodes Evidence as a RATSD v2 CBOR token.
func (e Evidence) ToCBOR() ([]byte, error) {
	return e.MarshalCBOR()
}

// FromCBOR decodes Evidence from a RATSD v2 CBOR token.
func (e *Evidence) FromCBOR(data []byte) error {
	return e.UnmarshalCBOR(data)
}

// Sign signs the Evidence collection as a COSE_Sign1 token using the supplied
// go-cose signer. The generated signature and algorithm are stored on the
// Evidence instance, and the serialized token is returned.
func (e *Evidence) Sign(signer cose.Signer) ([]byte, error) {
	if e == nil {
		return nil, errNilEvidence
	}
	if signer == nil {
		return nil, errors.New("nil signer")
	}

	payload, err := e.payloadCBOR()
	if err != nil {
		return nil, fmt.Errorf("COSE Sign1 signing failed: %w", err)
	}

	msg, err := e.sign1Message(payload)
	if err != nil {
		return nil, fmt.Errorf("COSE Sign1 signing failed: %w", err)
	}
	msg.Signature = nil
	msg.Headers.Protected.SetAlgorithm(signer.Algorithm())

	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("COSE Sign1 signing failed: %w", err)
	}

	e.Signature = cloneBytes(msg.Signature)
	alg := signer.Algorithm()
	e.ProtectedHeaders.Algorithm = &alg

	token, err := msg.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("COSE Sign1 marshaling failed: %w", err)
	}

	return token, nil
}

// Verify verifies the stored COSE_Sign1 signature using the supplied go-cose
// verifier.
func (e Evidence) Verify(verifier cose.Verifier) error {
	if verifier == nil {
		return errors.New("nil verifier")
	}

	payload, err := e.payloadCBOR()
	if err != nil {
		return fmt.Errorf("COSE Sign1 verification failed: %w", err)
	}

	msg, err := e.sign1Message(payload)
	if err != nil {
		return fmt.Errorf("COSE Sign1 verification failed: %w", err)
	}

	if err := msg.Verify(nil, verifier); err != nil {
		return fmt.Errorf("COSE Sign1 verification failed: %w", err)
	}

	return nil
}

// MarshalCBOR encodes Evidence as a tagged COSE_Sign1 token.
func (e Evidence) MarshalCBOR() ([]byte, error) {
	payload, err := e.payloadCBOR()
	if err != nil {
		return nil, fmt.Errorf("CBOR encoding failed: %w", err)
	}

	msg, err := e.sign1Message(payload)
	if err != nil {
		return nil, fmt.Errorf("CBOR encoding failed: %w", err)
	}

	token, err := msg.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("CBOR encoding failed: %w", err)
	}

	return token, nil
}

// UnmarshalCBOR decodes Evidence from a tagged COSE_Sign1 token.
func (e *Evidence) UnmarshalCBOR(data []byte) error {
	if e == nil {
		return errNilEvidence
	}

	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(data); err != nil {
		return fmt.Errorf("CBOR decoding failed: %w", err)
	}

	if len(msg.Headers.Unprotected) != 0 {
		return fmt.Errorf("CBOR decoding failed: unprotected headers MUST be empty")
	}

	protectedHeaders, err := protectedHeadersFromCOSE(msg.Headers.Protected)
	if err != nil {
		return fmt.Errorf("CBOR decoding failed: %w", err)
	}

	claims, collection, err := unmarshalPayload(msg.Payload)
	if err != nil {
		return fmt.Errorf("CBOR decoding failed: %w", err)
	}

	tmp := Evidence{
		ProtectedHeaders: protectedHeaders,
		Claims:           claims,
		Collection:       collection,
		Signature:        bytesOrEmpty(msg.Signature),
	}

	if err := tmp.Valid(); err != nil {
		return fmt.Errorf("CBOR decoding failed: %w", err)
	}

	*e = tmp
	return nil
}

// MarshalCBOR encodes the protected header map.
func (h ProtectedHeaders) MarshalCBOR() ([]byte, error) {
	protected, err := h.toCOSEProtectedHeader()
	if err != nil {
		return nil, err
	}

	return protected.MarshalCBOR()
}

// UnmarshalCBOR decodes the protected header map.
func (h *ProtectedHeaders) UnmarshalCBOR(data []byte) error {
	if h == nil {
		return errors.New("nil protected headers")
	}

	var protected cose.ProtectedHeader
	if err := protected.UnmarshalCBOR(data); err != nil {
		return fmt.Errorf("invalid protected headers: %w", err)
	}

	decoded, err := protectedHeadersFromCOSE(protected)
	if err != nil {
		return err
	}

	*h = decoded
	return nil
}

// MarshalCBOR encodes the tagged RATSD claims.
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

func (e Evidence) payloadCBOR() ([]byte, error) {
	if err := e.Valid(); err != nil {
		return nil, err
	}

	return marshalPayload(e.Claims, e.Collection)
}

func (e Evidence) sign1Message(payload []byte) (*cose.Sign1Message, error) {
	headers, err := e.ProtectedHeaders.toCOSEHeaders()
	if err != nil {
		return nil, err
	}

	msg := cose.NewSign1Message()
	msg.Headers = headers
	msg.Payload = bytesOrEmpty(payload)
	msg.Signature = cloneBytes(e.Signature)

	return msg, nil
}

func (h ProtectedHeaders) toCOSEHeaders() (cose.Headers, error) {
	protected, err := h.toCOSEProtectedHeader()
	if err != nil {
		return cose.Headers{}, err
	}

	return cose.Headers{
		Protected:   protected,
		Unprotected: cose.UnprotectedHeader{},
	}, nil
}

func (h ProtectedHeaders) toCOSEProtectedHeader() (cose.ProtectedHeader, error) {
	if err := h.Valid(); err != nil {
		return nil, err
	}

	protected := cose.ProtectedHeader{}
	if h.Algorithm != nil {
		protected.SetAlgorithm(*h.Algorithm)
	}

	switch len(h.X5Chain) {
	case 0:
	case 1:
		protected[cose.HeaderLabelX5Chain] = bytesOrEmpty(h.X5Chain[0])
	default:
		protected[cose.HeaderLabelX5Chain] = cloneByteSlices(h.X5Chain)
	}

	return protected, nil
}

func protectedHeadersFromCOSE(protected cose.ProtectedHeader) (ProtectedHeaders, error) {
	var decoded ProtectedHeaders

	for key, value := range protected {
		label, ok := int64Label(key)
		if !ok {
			return ProtectedHeaders{}, fmt.Errorf("invalid protected header label: %v", key)
		}

		switch label {
		case cose.HeaderLabelAlgorithm:
			alg, err := protected.Algorithm()
			if err != nil {
				return ProtectedHeaders{}, fmt.Errorf(`invalid protected header "alg": %w`, err)
			}
			decoded.Algorithm = &alg
		case cose.HeaderLabelX5Chain:
			x5chain, err := x5ChainFromHeaderValue(value)
			if err != nil {
				return ProtectedHeaders{}, err
			}
			decoded.X5Chain = x5chain
		default:
			return ProtectedHeaders{}, fmt.Errorf("invalid protected header label: %d", label)
		}
	}

	if err := decoded.Valid(); err != nil {
		return ProtectedHeaders{}, err
	}

	return decoded, nil
}

func x5ChainFromHeaderValue(value any) ([][]byte, error) {
	switch typed := value.(type) {
	case []byte:
		return [][]byte{bytesOrEmpty(typed)}, nil
	case [][]byte:
		if len(typed) < 2 {
			return nil, fmt.Errorf(`invalid protected header "x5chain": array form requires at least 2 certificates`)
		}
		return cloneByteSlices(typed), nil
	case []any:
		if len(typed) < 2 {
			return nil, fmt.Errorf(`invalid protected header "x5chain": array form requires at least 2 certificates`)
		}
		chain := make([][]byte, len(typed))
		for i, cert := range typed {
			certBytes, ok := cert.([]byte)
			if !ok {
				return nil, fmt.Errorf(`invalid protected header "x5chain": certificate at index %d has type %T`, i, cert)
			}
			chain[i] = bytesOrEmpty(certBytes)
		}
		return chain, nil
	default:
		return nil, fmt.Errorf(`invalid protected header "x5chain": %T`, value)
	}
}

func marshalPayload(claims Claims, collection cmw.CMW) ([]byte, error) {
	if err := claims.Valid(); err != nil {
		return nil, err
	}

	if err := validateUserCollection(collection); err != nil {
		return nil, err
	}

	encodedClaims, err := claims.MarshalCBOR()
	if err != nil {
		return nil, err
	}

	payload, err := cloneCMW(collection)
	if err != nil {
		return nil, err
	}

	if err := payload.AddCollectionItem(ratsdClaimsKey, cmw.NewMonad(ClaimsMediaType, encodedClaims)); err != nil {
		return nil, fmt.Errorf(`adding CMW collection field "__ratsd": %w`, err)
	}

	return payload.MarshalCBOR()
}

func unmarshalPayload(data []byte) (Claims, cmw.CMW, error) {
	var payload cmw.CMW
	if err := payload.UnmarshalCBOR(data); err != nil {
		return Claims{}, cmw.CMW{}, err
	}

	collectionType, err := payload.GetCollectionType()
	if err != nil {
		return Claims{}, cmw.CMW{}, errMissingCollectionType
	}
	if collectionType != CMWCollectionType {
		return Claims{}, cmw.CMW{}, fmt.Errorf(`invalid CMW collection field "__cmwc_t": expected %q`, CMWCollectionType)
	}

	claimsRecord, err := payload.GetCollectionItem(ratsdClaimsKey)
	if err != nil {
		return Claims{}, cmw.CMW{}, errMissingRATSDClaimsRecord
	}

	claims, err := unmarshalClaimsRecord(*claimsRecord)
	if err != nil {
		return Claims{}, cmw.CMW{}, err
	}

	collection := cmw.NewCollection(CMWCollectionType)
	if collection == nil {
		return Claims{}, cmw.CMW{}, fmt.Errorf("invalid RATSD CMW collection type constant: %s", CMWCollectionType)
	}

	meta, err := payload.GetCollectionMeta()
	if err != nil {
		return Claims{}, cmw.CMW{}, err
	}

	for _, itemMeta := range meta {
		key, ok := itemMeta.Key.(string)
		if !ok {
			return Claims{}, cmw.CMW{}, fmt.Errorf("invalid CMW collection key: want text, got %T", itemMeta.Key)
		}
		if key == ratsdClaimsKey {
			continue
		}
		if err := validateCollectionKey(key); err != nil {
			return Claims{}, cmw.CMW{}, err
		}

		item, err := payload.GetCollectionItem(key)
		if err != nil {
			return Claims{}, cmw.CMW{}, err
		}
		if err := validateCMWRecord(key, *item); err != nil {
			return Claims{}, cmw.CMW{}, err
		}

		itemClone, err := cloneCMW(*item)
		if err != nil {
			return Claims{}, cmw.CMW{}, fmt.Errorf("copying CMW record at key %q: %w", key, err)
		}
		if err := collection.AddCollectionItem(key, &itemClone); err != nil {
			return Claims{}, cmw.CMW{}, err
		}
	}

	if err := validateUserCollection(*collection); err != nil {
		return Claims{}, cmw.CMW{}, err
	}

	return claims, *collection, nil
}

func unmarshalClaimsRecord(record cmw.CMW) (Claims, error) {
	if record.GetKind() != cmw.KindMonad {
		return Claims{}, fmt.Errorf(`invalid CMW collection field "__ratsd": want CMW record, got %s`, record.GetKind())
	}

	if mediaType := record.GetMonadType(); mediaType != ClaimsMediaType {
		return Claims{}, fmt.Errorf(`invalid CMW collection field "__ratsd" type: expected %q`, ClaimsMediaType)
	}

	var claims Claims
	if err := claims.UnmarshalCBOR(record.GetMonadValue()); err != nil {
		return Claims{}, fmt.Errorf(`invalid CMW collection field "__ratsd" value: %w`, err)
	}

	return claims, nil
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

func validateCollectionKey(key string) error {
	switch key {
	case "":
		return errEmptyCollectionKey
	case cmwCollectionTypeKey, ratsdClaimsKey:
		return fmt.Errorf("invalid CMW collection key %q: reserved", key)
	default:
		return nil
	}
}

func validateUserCollection(collection cmw.CMW) error {
	if err := validateCollectionForToken(collection); err != nil {
		return err
	}

	meta, err := collection.GetCollectionMeta()
	if err != nil {
		return err
	}
	if len(meta) == 0 {
		return errMissingCollectionRecord
	}

	return nil
}

func validateCollectionForToken(collection cmw.CMW) error {
	if collection.GetKind() != cmw.KindCollection {
		return fmt.Errorf("want CMW collection, got %s", collection.GetKind())
	}

	collectionType, err := collection.GetCollectionType()
	if err != nil {
		return errMissingCollectionType
	}
	if collectionType != CMWCollectionType {
		return fmt.Errorf(`invalid CMW collection field "__cmwc_t": expected %q`, CMWCollectionType)
	}

	meta, err := collection.GetCollectionMeta()
	if err != nil {
		return err
	}

	for _, itemMeta := range meta {
		key, ok := itemMeta.Key.(string)
		if !ok {
			return fmt.Errorf("invalid CMW collection key: want text, got %T", itemMeta.Key)
		}
		if err := validateCollectionKey(key); err != nil {
			return err
		}

		item, err := collection.GetCollectionItem(key)
		if err != nil {
			return err
		}
		if err := validateCMWRecord(key, *item); err != nil {
			return err
		}
	}

	return nil
}

func validateCMWRecord(key string, record cmw.CMW) error {
	if record.GetKind() != cmw.KindMonad {
		return fmt.Errorf("invalid CMW record at key %q: want CMW record, got %s", key, record.GetKind())
	}

	switch record.GetFormat() {
	case cmw.FormatUnknown, cmw.FormatCBORRecord:
	default:
		return fmt.Errorf("invalid CMW record at key %q: want CBOR record, got %s", key, record.GetFormat())
	}

	if record.GetMonadType() == "" {
		return fmt.Errorf("invalid CMW record at key %q: missing mandatory CMW record type", key)
	}

	if len(record.GetMonadValue()) == 0 {
		return fmt.Errorf("invalid CMW record at key %q: %w", key, errMissingCMWRecordValue)
	}

	return nil
}

func intLabel(v any) (int, bool) {
	label, ok := int64Label(v)
	if !ok || label < math.MinInt || label > math.MaxInt {
		return 0, false
	}

	return int(label), true
}

func int64Label(v any) (int64, bool) {
	switch typed := v.(type) {
	case int64:
		return typed, true
	case uint64:
		if typed > math.MaxInt64 {
			return 0, false
		}
		return int64(typed), true
	case int:
		return int64(typed), true
	case uint:
		if uint64(typed) > math.MaxInt64 {
			return 0, false
		}
		return int64(typed), true
	default:
		return 0, false
	}
}

func bytesOrEmpty(v []byte) []byte {
	if v == nil {
		return []byte{}
	}

	return cloneBytes(v)
}

func cloneBytes(v []byte) []byte {
	if v == nil {
		return nil
	}

	return append([]byte(nil), v...)
}

func cloneByteSlices(v [][]byte) [][]byte {
	if v == nil {
		return nil
	}

	clone := make([][]byte, len(v))
	for i, item := range v {
		clone[i] = bytesOrEmpty(item)
	}

	return clone
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

func cloneCMW(v cmw.CMW) (cmw.CMW, error) {
	encoded, err := v.MarshalCBOR()
	if err != nil {
		return cmw.CMW{}, err
	}

	var clone cmw.CMW
	if err := clone.UnmarshalCBOR(encoded); err != nil {
		return cmw.CMW{}, err
	}

	return clone, nil
}
