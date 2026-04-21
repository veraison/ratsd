package token

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/veraison/cmw"
	cose "github.com/veraison/go-cose"
)

const (
	ratsdMediaType         = "tag:github.com,2025:veraison/ratsd/cmw"
	CWTClaimsNonce   int64 = 10
	CWTClaimsProfile int64 = 265
)

const ()

// Evidence is the wrapper around the RATSD token, including the COSE envelope and
// the underlying CMWCollection
// nolint: golint
type Evidence struct {
	token             *cmw.CMW
	Header            cose.CWTClaims
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
	h := make(cose.CWTClaims)
	h[CWTClaimsProfile] = ratsdMediaType

	return &Evidence{token: ev, Header: h, message: msg}, nil
}

func NewEvidenceWithParams() (*Evidence, error) {
	return nil, nil
}

func (e *Evidence) AddNonce(nonce []byte) error {
	if e.Header == nil {
		return errors.New("no header present in the Evidence")
	}
	e.Header[CWTClaimsNonce] = nonce
	return nil
}

// AddToken adds a particular Token Type to the RATSD Evidence
func (e *Evidence) AddToken(key string, evMt string, token []byte) error {
	node, err := cmw.NewMonad(evMt, token)
	if err != nil {
		return fmt.Errorf("unable to add the token %w", err)
	}
	if err := e.token.AddCollectionItem(key, node); err != nil {
		return fmt.Errorf("unable to add the collection item %w", err)
	}

	return nil
}

// ValidateAndSign returns the Evidence wrapped in a CWT according to the supplied
// go-cose Signer.
func (e *Evidence) ValidateAndSign(signer cose.Signer) ([]byte, error) {

	var err error
	if e.token == nil {
		return nil, errors.New("token does not exist")
	}
	if err := e.token.Valid(); err != nil {
		return nil, fmt.Errorf("invalid CMW Collection %w", err)
	}

	e.message.Payload, err = e.token.MarshalCBOR()
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
	if e.Header == nil {
		return errors.New("no CWT Header in evidence")
	}
	_, ok := e.Header[CWTClaimsProfile]
	if !ok {
		return errors.New("missing profile")
	}

	_, ok = e.Header[CWTClaimsNonce]
	if !ok {
		return errors.New("missing nonce")
	}

	if e.token == nil {
		return errors.New("token does not exist")
	}
	if err := e.token.Valid(); err != nil {
		return fmt.Errorf("invalid CMW Collection %w", err)
	}
	return nil
}

// Verify

// UnMarshal

// Consider X5Chain, signing Certificate, One or More..

// Protected Header should have x5t, There is some thumbprint...
