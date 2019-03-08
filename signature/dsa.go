package signature

import (
	"crypto/dsa"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/cyclic"
	"io"
)

type ParameterSizes dsa.ParameterSizes

const (
	L1024N160 ParameterSizes = iota
	L2048N224
	L2048N256
	L3072N256
)

func CustomDSAParams(P, Q, G *cyclic.Int) *DSAParameters {
	return &DSAParameters{dsa.Parameters{P.GetBigInt(), Q.GetBigInt(), G.GetBigInt()}}
}

func NewDSAParams(rng io.Reader, pSize ParameterSizes) *DSAParameters {

	dsaParams := DSAParameters{}

	err := dsa.GenerateParameters(&dsaParams.Params, rng, dsa.ParameterSizes(pSize))

	if err != nil {
		jww.FATAL.Panicf("Unable to generate parameters", err.Error())
	}

	return &dsaParams
}

type DSAParameters struct {
	Params dsa.Parameters
}

func (p *DSAParameters) PrivateKeyGen(rng io.Reader) *DSAPrivateKey {

	pk := DSAPrivateKey{}
	pk.Key.Parameters = p.Params

	err := dsa.GenerateKey(&pk.Key, rng)

	if err != nil {
		jww.FATAL.Panicf("Unable to generate DSA private key", err.Error())
	}

	return &pk
}

type DSAPrivateKey struct {
	Key dsa.PrivateKey
}

func (p *DSAPrivateKey) PublicKeyGen() *DSAPublicKey {
	return &DSAPublicKey{p.Key.PublicKey}
}

func (p *DSAPrivateKey) Sign(data []byte, rng io.Reader) (*DSASignature, error) {

	r, s, err := dsa.Sign(rng, &p.Key, data)

	rCyclic := cyclic.NewIntFromBigInt(r)
	sCyclic := cyclic.NewIntFromBigInt(s)

	return &DSASignature{rCyclic, sCyclic}, err

}

type DSAPublicKey struct {
	Key dsa.PublicKey
}

func (p *DSAPublicKey) Verify(hash []byte, sig DSASignature) bool {
	return dsa.Verify(&p.Key, hash, sig.R.GetBigInt(), sig.S.GetBigInt())
}

type DSASignature struct {
	R *cyclic.Int
	S *cyclic.Int
}

// Gob encode/decode

func (p *DSAParameters) GobDecode(b []byte) error {
	return decode(b, &p.Params)
}

func (p *DSAParameters) GobEncode() ([]byte, error) {
	return encode(p.Params)
}

func (p *DSAPrivateKey) GobDecode(b []byte) error {
	return decode(b, &p.Key)
}

func (p *DSAPrivateKey) GobEncode() ([]byte, error) {
	return encode(p.Key)
}

func (p *DSAPublicKey) GobDecode(b []byte) error {
	return decode(b, &p.Key)
}

func (p *DSAPublicKey) GobEncode() ([]byte, error) {
	return encode(p.Key)
}

func (p *DSASignature) GobDecode(b []byte) error {
	return decode(b, &p)
}

func (p *DSASignature) GobEncode() ([]byte, error) {
	return encode(p)
}
