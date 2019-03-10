package signature

import (
	"bytes"
	"crypto/dsa"
	"encoding/gob"
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

func CustomDSAParams(sizes ParameterSizes, P, Q, G *cyclic.Int) *DSAParameters {
	return &DSAParameters{ dsa.Parameters{P: P.GetBigInt(), Q: Q.GetBigInt(), G: G.GetBigInt()}, sizes}
}

func NewDSAParams(rng io.Reader, pSize ParameterSizes) *DSAParameters {

	dsaParams := DSAParameters{}

	err := dsa.GenerateParameters(&dsaParams.params, rng, dsa.ParameterSizes(pSize))

	if err != nil {
		jww.FATAL.Panicf("Unable to generate parameters")
	}

	return &dsaParams
}

type DSAParameters struct {
	params dsa.Parameters
	sizes ParameterSizes
}

func (p *DSAParameters) PrivateKeyGen(rng io.Reader) *DSAPrivateKey {

	pk := DSAPrivateKey{}
	pk.key.Parameters = p.params
	pk.key.Q = p.params.Q

	err := dsa.GenerateParameters(&pk.key.Parameters, rng, (dsa.ParameterSizes)(p.sizes) )

	if err != nil {
		jww.FATAL.Panicf("Unable to generate DSA params")
	}

	err = dsa.GenerateKey(&pk.key, rng)

	if err != nil {
		jww.FATAL.Panicf("Unable to generate DSA private key")
	}

	return &pk
}

func (p *DSAParameters) GetG() *cyclic.Int {
	return cyclic.NewIntFromBigInt(p.params.G)
}

func (p *DSAParameters) GetP() *cyclic.Int {
	return cyclic.NewIntFromBigInt(p.params.P)
}

func (p *DSAParameters) GetQ() *cyclic.Int {
	return cyclic.NewIntFromBigInt(p.params.Q)
}

func (k *DSAPublicKey) GetG() *cyclic.Int {
	return cyclic.NewIntFromBigInt(k.key.G)
}

func (k *DSAPublicKey) GetP() *cyclic.Int {
	return cyclic.NewIntFromBigInt(k.key.P)
}

func (k *DSAPublicKey) GetQ() *cyclic.Int {
	return cyclic.NewIntFromBigInt(k.key.Q)
}

func (k *DSAPublicKey) GetY() *cyclic.Int {
	return cyclic.NewIntFromBigInt(k.key.Y)
}

type DSAPrivateKey struct {
	key dsa.PrivateKey
}

func (p *DSAPrivateKey) PublicKeyGen() *DSAPublicKey {
	return &DSAPublicKey{p.key.PublicKey}
}

func (p *DSAPrivateKey) Sign(data []byte, rng io.Reader) (*DSASignature, error) {

	r, s, err := dsa.Sign(rng, &p.key, data)

	rCyclic := cyclic.NewIntFromBigInt(r)
	sCyclic := cyclic.NewIntFromBigInt(s)

	return &DSASignature{rCyclic, sCyclic}, err

}

func (p *DSAPrivateKey) GetKey() *cyclic.Int {
	return cyclic.NewIntFromBigInt(p.key.X)
}

func (dsaKey *DSAPrivateKey) GetPublicKey() *cyclic.Int {
	return cyclic.NewIntFromBigInt(dsaKey.key.PublicKey.Y)
}

func (dsaKey *DSAPrivateKey) GetParams() (p, q, g *cyclic.Int) {
	p = cyclic.NewIntFromBigInt(dsaKey.key.P)
	q = cyclic.NewIntFromBigInt(dsaKey.key.Q)
	g = cyclic.NewIntFromBigInt(dsaKey.key.G)
	return p, q, g
}

func ReconstructPrivateKey(publicKey *DSAPublicKey, privateKey *cyclic.Int) *DSAPrivateKey {
	pk := &DSAPrivateKey{}

	pk.key.PublicKey = publicKey.key
	pk.key.X = privateKey.GetBigInt()

	return pk
}

type DSAPublicKey struct {
	key dsa.PublicKey
}

func ReconstructPublicKey(p *DSAParameters, key *cyclic.Int) *DSAPublicKey {
	pk := &DSAPublicKey{}
	pk.key.Parameters = p.params
	pk.key.Y = key.GetBigInt()

	return pk
}

func (p *DSAPublicKey) Verify(hash []byte, sig DSASignature) bool {
	return dsa.Verify(&p.key, hash, sig.R.GetBigInt(), sig.S.GetBigInt())
}

func (p *DSAPublicKey) GetKey() *cyclic.Int {
	return cyclic.NewIntFromBigInt(p.key.Y)
}

type DSASignature struct {
	R *cyclic.Int
	S *cyclic.Int
}

// Gob encode/decode

func decode(b []byte, e interface{}) error {
	var buffer bytes.Buffer

	buffer.Read(b)

	dec := gob.NewDecoder(&buffer)

	return dec.Decode(e)
}

func encode(e interface{}) ([]byte, error) {
	var buffer bytes.Buffer

	enc := gob.NewEncoder(&buffer)

	err := enc.Encode(e)

	return buffer.Bytes(), err
}

func (p *DSAParameters) GobDecode(b []byte) error {
	return decode(b, &p.params)
}

func (p *DSAParameters) GobEncode() ([]byte, error) {
	return encode(p.params)
}

func (p *DSAPrivateKey) GobDecode(b []byte) error {
	return decode(b, &p.key)
}

func (p *DSAPrivateKey) GobEncode() ([]byte, error) {
	return encode(p.key)
}

func (p *DSAPublicKey) GobDecode(b []byte) error {
	return decode(b, &p.key)
}

func (p *DSAPublicKey) GobEncode() ([]byte, error) {
	return encode(p.key)
}

func (p *DSASignature) GobDecode(b []byte) error {
	return decode(b, &p)
}

func (p *DSASignature) GobEncode() ([]byte, error) {
	return encode(p)
}
