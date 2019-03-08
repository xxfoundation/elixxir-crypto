package registration

import (
	"crypto/dsa"
)

type DSAParameters struct {
	params dsa.Parameters
}

func (p DSAParameters) ParametersMetadata() string {
	return "DSAParameters"
}

func (p DSAParameters) GobDecode(b []byte) error {
	return decode(b, p.params)
}

func (p DSAParameters) GobEncode() ([]byte, error) {
	return encode(p.params)
}

type DSAPrivateKey struct {
	privateKey dsa.PrivateKey
}



type DSAPublicKey struct {
	publicKey dsa.PublicKey
}

type DSAScheme struct {
}

// Implementation of DSA scheme
func (s DSAScheme) SchemeMetadata() string {
	return "DSAScheme"
}

func (s DSAScheme) KeyGen(p Parameters) (PublicKey, PrivateKey) {
	return nil, nil
}

func (s DSAScheme) Sign([]byte, PrivateKey) []byte {
	return nil
}

func (s DSAScheme) Verify([]byte, PublicKey) bool {
	return false
}

func (s DSAScheme) GobEncode() ([]byte, error) {
	return nil, nil
}

func (s DSAScheme) GobDecode(b []byte) error {
	return nil
}
