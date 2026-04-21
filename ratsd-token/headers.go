package token

const (
	CWTClaimsNonce   int64 = 10
	CWTClaimsProfile int64 = 265
)

type CWTClaims map[any]any

func NewClaims() CWTClaims {
	return make(CWTClaims)
}

func (c CWTClaims) AddNonce(n []byte) {
	c[CWTClaimsNonce] = n
}

func (c CWTClaims) AddProfile(p string) {
	c[CWTClaimsProfile] = p
}
