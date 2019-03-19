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

const (
	DSA_GROUP_P = "9DB6FB5951B66BB6FE1E140F1D2CE5502374161FD6538DF1648218642F0B5C48" +
		"C8F7A41AADFA187324B87674FA1822B00F1ECF8136943D7C55757264E5A1A44F" +
		"FE012E9936E00C1D3E9310B01C7D179805D3058B2A9F4BB6F9716BFE6117C6B5" +
		"B3CC4D9BE341104AD4A80AD6C94E005F4B993E14F091EB51743BF33050C38DE2" +
		"35567E1B34C3D6A5C0CEAA1A0F368213C3D19843D0B4B09DCB9FC72D39C8DE41" +
		"F1BF14D4BB4563CA28371621CAD3324B6A2D392145BEBFAC748805236F5CA2FE" +
		"92B871CD8F9C36D3292B5509CA8CAA77A2ADFC7BFD77DDA6F71125A7456FEA15" +
		"3E433256A2261C6A06ED3693797E7995FAD5AABBCFBE3EDA2741E375404AE25B"

	DSA_GROUP_Q = "F2C3119374CE76C9356990B465374A17F23F9ED35089BD969F61C6DDE9998C1F"

	DSA_GROUP_G = "5C7FF6B06F8F143FE8288433493E4769C4D988ACE5BE25A0E24809670716C613" +
		"D7B0CEE6932F8FAA7C44D2CB24523DA53FBE4F6EC3595892D1AA58C4328A06C4" +
		"6A15662E7EAA703A1DECF8BBB2D05DBE2EB956C142A338661D10461C0D135472" +
		"085057F3494309FFA73C611F78B32ADBB5740C361C9F35BE90997DB2014E2EF5" +
		"AA61782F52ABEB8BD6432C4DD097BC5423B285DAFB60DC364E8161F4A2A35ACA" +
		"3A10B1C4D203CC76A470A33AFDCBDD92959859ABD8B56E1725252D78EAC66E71" +
		"BA9AE3F1DD2487199874393CD4D832186800654760E1E34C09E4D155179F9EC0" +
		"DC4473F996BDCE6EED1CABED8B6F116F7AD9CF505DF0F998E34AB27514B0FFE7"
)

func GetDefaultDSAParams() *DSAParameters {
	bigP := cyclic.NewIntFromString(DSA_GROUP_P, 16)
	bigQ := cyclic.NewIntFromString(DSA_GROUP_Q, 16)
	bigG := cyclic.NewIntFromString(DSA_GROUP_G, 16)
	jww.WARN.Printf("Using hardcoded DSA Params, should be removed in the future!")
	return CustomDSAParams(bigP, bigQ, bigG)
}

func CustomDSAParams(P, Q, G *cyclic.Int) *DSAParameters {
	return &DSAParameters{dsa.Parameters{P: P.GetBigInt(), Q: Q.GetBigInt(), G: G.GetBigInt()}}
}

func NewDSAParams(rng io.Reader, pSizes ParameterSizes) *DSAParameters {

	dsaParams := DSAParameters{}

	err := dsa.GenerateParameters(&dsaParams.params, rng, dsa.ParameterSizes(pSizes))

	if err != nil {
		jww.FATAL.Panicf("Unable to generate parameters")
	}

	return &dsaParams
}

type DSAParameters struct {
	params dsa.Parameters
}

func (p *DSAParameters) PrivateKeyGen(rng io.Reader) *DSAPrivateKey {

	pk := DSAPrivateKey{}
	pk.key.Parameters = p.params

	err := dsa.GenerateKey(&pk.key, rng)

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

func (k *DSAPublicKey) GetParams() *DSAParameters {
	return &DSAParameters{params: k.key.Parameters}
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

// TODO: Add tests for Gob encode/decode and uncomment impl.
//func decode(b []byte, e interface{}) error {
//	var buffer bytes.Buffer
//
//	buffer.Read(b)
//
//	dec := gob.NewDecoder(&buffer)
//
//	return dec.Decode(e)
//}
//
//func encode(e interface{}) ([]byte, error) {
//	var buffer bytes.Buffer
//
//	enc := gob.NewEncoder(&buffer)
//
//	err := enc.Encode(e)
//
//	return buffer.Bytes(), err
//}
//
//func (p *DSAParameters) GobDecode(b []byte) error {
//	return decode(b, &p.params)
//}
//
//func (p *DSAParameters) GobEncode() ([]byte, error) {
//	return encode(p.params)
//}
//
//func (p *DSAPrivateKey) GobDecode(b []byte) error {
//	return decode(b, &p.key)
//}
//
//func (p *DSAPrivateKey) GobEncode() ([]byte, error) {
//	return encode(p.key)
//}
//
//func (p *DSAPublicKey) GobDecode(b []byte) error {
//	return decode(b, &p.key)
//}
//
//func (p *DSAPublicKey) GobEncode() ([]byte, error) {
//	return encode(p.key)
//}
//
//func (p *DSASignature) GobDecode(b []byte) error {
//	return decode(b, &p)
//}
//
//func (p *DSASignature) GobEncode() ([]byte, error) {
//	return encode(p)
//}