package token

import (
	cbor "github.com/fxamacker/cbor/v2"
	"github.com/veraison/eat"
)

const ratsdProfile = "tag:github.com,2026:veraison/ratsd/v2"
const UCCSTag uint64 = 601

type Claims struct {
	Profile *eat.Profile `cbor:"265,keyasint"`
	Nonce   *eat.Nonce   `cbor:"10,keyasint"`

	Nonce_adjust_fn  string          `cbor:"-65537,keyasint"`
	Nonce_adjust_map map[string]uint `cbor:"-65538,keyasint"`
}

func newClaims() *Claims {
	p := eat.Profile{}
	if err := p.Set(ratsdProfile); err != nil {
		// should never get here as using known good constant as input
		panic(err)
	}
	return &Claims{
		Profile: &p,
	}
}

func (c *Claims) SetNonce(v []byte) error {
	// TO DO Check for Valid Size
	n := eat.Nonce{}
	if err := n.Add(v); err != nil {
		return err
	}
	c.Nonce = &n
	return nil
}

// Valid check if the Claims is Valid
func (c Claims) Valid() error {

	return nil
}

func MarshalUCCS(claims *Claims) ([]byte, error) {

	return em.Marshal(cbor.Tag{
		Number:  UCCSTag,
		Content: *claims,
	})
}
