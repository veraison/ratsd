package token

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/veraison/cmw"
	cose "github.com/veraison/go-cose"
)

const (
	ratsdMediaType         = "tag:github.com,2025:veraison/ratsd/cmw/v2"
	CWTClaimsNonce   int64 = 10
	CWTClaimsProfile int64 = 265
	ContentType            = "application/veraison+ratsd/cmw"
)

// Evidence is the wrapper around the RATSD token, including the COSE envelope and
// the underlying CMWCollection
// nolint: golint
type Evidence struct {
	collection        *cmw.CMW
	claims            *Claims
	SigningCert       *x509.Certificate
	IntermediateCerts []*x509.Certificate
	message           *cose.Sign1Message
}

type Option func(*Evidence)

func NewEvidence() (*Evidence, error) {
	ev, err := cmw.NewCollection(ratsdMediaType)
	msg := cose.NewSign1Message()
	if err != nil {
		return nil, err
	}

	claims := newClaims()
	return &Evidence{collection: ev, claims: claims, message: msg}, nil
}

func (e *Evidence) AddNonce(nonce []byte) error {
	if e.claims != nil {
		return fmt.Errorf("claims do not exist")
	}
	if err := e.claims.SetNonce(nonce); err != nil {
		return err
	}
	return nil
}

// AddToken adds a particular Token Type to the RATSD Evidence
func (e *Evidence) AddToken(key string, evMt string, token []byte) error {
	node, err := cmw.NewMonad(evMt, token)
	if err != nil {
		return fmt.Errorf("unable to add the token %w", err)
	}
	if err := e.collection.AddCollectionItem(key, node); err != nil {
		return fmt.Errorf("unable to add the collection item %w", err)
	}

	return nil
}

// ValidateAndSign returns the Evidence wrapped in a CWT according to the supplied
// go-cose Signer.
func (e *Evidence) ValidateAndSign(signer cose.Signer) ([]byte, error) {

	var err error
	if e.collection == nil {
		return nil, errors.New("collection does not exist")
	}
	if err := e.collection.Valid(); err != nil {
		return nil, fmt.Errorf("invalid CMW Collection %w", err)
	}

	e.message.Payload, err = e.collection.MarshalCBOR()
	if err != nil {
		return nil, err
	}

	return e.doSign(signer)

}

func (e *Evidence) doSign(signer cose.Signer) ([]byte, error) {
	alg := signer.Algorithm()

	if strings.Contains(alg.String(), "unknown algorithm value") {
		return nil, errors.New("signer has no algorithm")
	}

	e.message.Headers.Protected.SetAlgorithm(alg)
	e.message.Headers.Protected.SetCWTClaims(e.Header)
	if e.SigningCert != nil {
		// COSE_X509 = bstr / [ 2*certs: bstr ]
		//
		// handle alt (1): bstr
		if len(e.IntermediateCerts) == 0 {
			e.message.Headers.Protected[cose.HeaderLabelX5Chain] = e.SigningCert.Raw
		} else { // handle alt (2): [ 2*certs: bstr ]
			certChain := [][]byte{e.SigningCert.Raw}
			for _, cert := range e.IntermediateCerts {
				certChain = append(certChain, cert.Raw)
			}
			e.message.Headers.Protected[cose.HeaderLabelX5Chain] = certChain
		}
	} else if e.IntermediateCerts != nil {
		return nil, errors.New("intermediate certificates supplied but no signing certificate")
	}

	err := e.message.Sign(rand.Reader, []byte(""), signer)
	if err != nil {
		return nil, err
	}

	wrap, err := e.message.MarshalCBOR()
	if err != nil {
		return nil, err
	}

	return wrap, nil
}

// AddSigningCert adds a DER-encoded X.509 certificate to be included in the
// protected header of the COSE Sign1 message as the leaf certificate in X5Chain.
func (e *Evidence) AddSigningCert(der []byte) error {
	if der == nil {
		return errors.New("nil signing cert")
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("invalid signing certificate: %w", err)
	}

	e.SigningCert = cert
	return nil
}

// AddIntermediateCerts adds DER-encoded X.509 certificates to be included in the protected
// header of the COSE Sign1 message as part of the X5Chain.
// The certificates must be concatenated with no intermediate padding, as per X.509 convention.
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

func (e Evidence) Valid() error {

	if e.collection == nil {
		return errors.New("collection does not exist")
	}
	if err := e.collection.Valid(); err != nil {
		return fmt.Errorf("invalid CMW Collection %w", err)
	}
	return nil
}

// Verify

// UnMarshal
func (e *Evidence) UnmarshalCOSE(cwt []byte) error {
	var err error

	e.message = cose.NewSign1Message()

	if err = e.message.UnmarshalCBOR(cwt); err != nil {
		return fmt.Errorf("failed CBOR decoding for CWT: %w", err)
	}
	payload := e.message.Payload
	e.collection = &cmw.CMW{}
	if err := e.collection.UnmarshalCBOR(payload); err != nil {
		return err
	}

	return nil
}

func (e *Evidence) processHdrs() error {

	var hdr = e.message.Headers

	if hdr.Protected == nil {
		return errors.New("missing mandatory protected header")
	}

	if v, ok := hdr.Protected[cose.HeaderLabelContentType]; ok {
		if v != ContentType {
			return fmt.Errorf("expecting content type %q, got %q instead", ContentType, v)
		}
	} else {
		return errors.New("missing mandatory content type")
	}

	// Process optional x5chain
	if v, ok := hdr.Protected[cose.HeaderLabelX5Chain]; ok {
		if err := e.extractX5Chain(v); err != nil {
			return err
		}
	}

	_, ok := hdr.Protected[CWTClaimsProfile]
	if !ok {
		return errors.New("missing profile")
	}

	_, ok = hdr.Protected[CWTClaimsNonce]
	if !ok {
		return errors.New("missing nonce")
	}

	return nil

}

func (e *Evidence) extractX5Chain(x5chain interface{}) error {
	var buf bytes.Buffer

	switch t := x5chain.(type) {
	case []interface{}:
		for i, elem := range t {
			cert, ok := elem.([]byte)
			if !ok {
				return fmt.Errorf("accessing x5chain[%d]: got %T, want []byte", i, elem)
			}

			switch i {
			case 0:
				if err := e.AddSigningCert(cert); err != nil {
					return fmt.Errorf("decoding x5chain: %w", err)
				}
			default:
				buf.Write(cert)
			}
		}

		if buf.Len() > 0 {
			if err := e.AddIntermediateCerts(buf.Bytes()); err != nil {
				return fmt.Errorf("decoding x5chain: %w", err)
			}
		}
	case []byte:
		if err := e.AddSigningCert(t); err != nil {
			return fmt.Errorf("decoding x5chain: %w", err)
		}
	default:
		return fmt.Errorf("decoding x5chain: got %T, want []interface{} or []byte", t)
	}

	return nil

}

// Consider X5Chain, signing Certificate, One or More..

// Protected Header should have x5t, There is some thumbprint...
