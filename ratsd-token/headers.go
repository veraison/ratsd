package token

import "github.com/veraison/go-cose"

const (
	CWTClaimsNonce   int64 = 10
	CWTClaimsProfile int64 = 265
)

type CWTClaims cose.CWTClaims

var ratsdClaims CWTClaims

func NewratsdCwtMap() CWTClaims {
	ratsdClaims := make(CWTClaims)
	return ratsdClaims
}

func GetratsdCwtMap() CWTClaims {
	return ratsdClaims
}

func (r CWTClaims) Addprofile(p string) {
	r[CWTClaimsProfile] = p
}

func (r CWTClaims) AddNonce(n []byte) {
	r[CWTClaimsNonce] = n
}

// Check all Mandatory Claims Keys are present or not??
func (r CWTClaims) Valid() error {

	return nil
}
