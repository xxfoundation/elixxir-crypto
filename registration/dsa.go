package registration

import (
	"bufio"
	"bytes"
	"crypto/dsa"
	"encoding/gob"
	"io"
)

type DSAParameters struct {
	params dsa.Parameters
}

func (p DSAParameters) ParametersMetadata() string {
	return "DSAParameters"
}

func (p DSAParameters) GobDecode(b []byte) error {
	reader := bufio.NewReader(b)

	dec := gob.NewDecoder(reader)

	return dec.Decode(p.params)
}

func (p DSAParameters) GobEncode() ([]byte, error) {
	var buffer bytes.Buffer

	enc := gob.NewEncoder(&buffer)

	err := enc.Encode(p.params)

	return buffer.Bytes(), err
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
