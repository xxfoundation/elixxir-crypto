package signature

import (
	"bytes"
	"crypto/dsa"
	"encoding/gob"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/large"
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
	bigP := large.NewIntFromString(DSA_GROUP_P, 16)
	bigQ := large.NewIntFromString(DSA_GROUP_Q, 16)
	bigG := large.NewIntFromString(DSA_GROUP_G, 16)
	jww.WARN.Printf("Using hardcoded DSA Params, should be removed in the future!")
	return CustomDSAParams(bigP, bigQ, bigG)
}

func CustomDSAParams(P, Q, G large.Int) *DSAParameters {
	return &DSAParameters{dsa.Parameters{P: P.BigInt(), Q: Q.BigInt(), G: G.BigInt()}}
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

// Returns a byte slice representing the encoding of DSAParameters for the
// transmission to a GobDecode().
func (p *DSAParameters) GobEncode() ([]byte, error) {
	// Anonymous structure
	s := struct {
		P []byte
		Q []byte
		G []byte
	}{
		p.params.P.Bytes(),
		p.params.Q.Bytes(),
		p.params.G.Bytes(),
	}

	var buf bytes.Buffer

	// Create new encoder that will transmit the buffer
	enc := gob.NewEncoder(&buf)

	// Transmit the data
	err := enc.Encode(s)

	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Overwrites the receiver, which must be a pointer, with DSAParameters
// represented by the byte slice, which was written by GobEncode().
func (p *DSAParameters) GobDecode(b []byte) error {
	// , empty structure
	s := struct {
		P []byte
		Q []byte
		G []byte
	}{
		[]byte{},
		[]byte{},
		[]byte{},
	}

	var buf bytes.Buffer

	// Write bytes to the buffer
	buf.Write(b)

	// Create new decoder that reads from the buffer
	dec := gob.NewDecoder(&buf)

	// Receive and decode data
	err := dec.Decode(&s)

	if err != nil {
		return err
	}

	// Convert decoded bytes and put into empty structure
	p.params.P = large.NewIntFromBytes(s.P).BigInt()
	p.params.Q = large.NewIntFromBytes(s.Q).BigInt()
	p.params.G = large.NewIntFromBytes(s.G).BigInt()

	return nil
}

func (p *DSAParameters) GetG() large.Int {
	return large.NewIntFromBigInt(p.params.G)
}

func (p *DSAParameters) GetP() large.Int {
	return large.NewIntFromBigInt(p.params.P)
}

func (p *DSAParameters) GetQ() large.Int {
	return large.NewIntFromBigInt(p.params.Q)
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

// Returns a byte slice representing the encoding of DSAPrivateKey for the
// transmission to a GobDecode().
func (p *DSAPrivateKey) GobEncode() ([]byte, error) {
	// Anonymous structure that flattens nested structures
	s := struct {
		P []byte
		Q []byte
		G []byte
		Y []byte
		X []byte
	}{
		p.key.PublicKey.Parameters.P.Bytes(),
		p.key.PublicKey.Parameters.Q.Bytes(),
		p.key.PublicKey.Parameters.G.Bytes(),
		p.key.PublicKey.Y.Bytes(),
		p.key.X.Bytes(),
	}

	var buf bytes.Buffer

	// Create new encoder that will transmit the buffer
	enc := gob.NewEncoder(&buf)

	// Transmit the data
	err := enc.Encode(s)

	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Overwrites the receiver, which must be a pointer, with DSAPrivateKey
// represented by the byte slice, which was written by GobEncode().
func (p *DSAPrivateKey) GobDecode(b []byte) error {
	// Anonymous, empty, flat structure
	s := struct {
		P []byte
		Q []byte
		G []byte
		X []byte
		Y []byte
	}{
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
	}

	var buf bytes.Buffer

	// Write bytes to the buffer
	buf.Write(b)

	// Create new decoder that reads from the buffer
	dec := gob.NewDecoder(&buf)

	// Receive and decode data
	err := dec.Decode(&s)

	if err != nil {
		return err
	}

	// Convert decoded bytes and put into empty structure
	p.key.PublicKey.Parameters.P = large.NewIntFromBytes(s.P).BigInt()
	p.key.PublicKey.Parameters.Q = large.NewIntFromBytes(s.Q).BigInt()
	p.key.PublicKey.Parameters.G = large.NewIntFromBytes(s.G).BigInt()
	p.key.PublicKey.Y = large.NewIntFromBytes(s.Y).BigInt()
	p.key.X = large.NewIntFromBytes(s.X).BigInt()

	return nil
}

func (p *DSAPrivateKey) Sign(data []byte, rng io.Reader) (*DSASignature, error) {

	r, s, err := dsa.Sign(rng, &p.key, data)

	rval := large.Int(nil)
	sval := large.Int(nil)

	if err == nil {
		rval = large.NewIntFromBigInt(r)
		sval = large.NewIntFromBigInt(s)
	}

	return &DSASignature{rval, sval}, err
}

func (p *DSAPrivateKey) GetKey() large.Int {
	return large.NewIntFromBigInt(p.key.X)
}

func ReconstructPrivateKey(publicKey *DSAPublicKey, privateKey large.Int) *DSAPrivateKey {
	pk := &DSAPrivateKey{}

	pk.key.PublicKey = publicKey.key
	pk.key.X = privateKey.BigInt()

	return pk
}

type DSAPublicKey struct {
	key dsa.PublicKey
}

func ReconstructPublicKey(p *DSAParameters, key large.Int) *DSAPublicKey {
	pk := &DSAPublicKey{}
	pk.key.Parameters = p.params
	pk.key.Y = key.BigInt()

	return pk
}

// Returns a byte slice representing the encoding of DSAPublicKey for the
// transmission to a GobDecode().
func (p *DSAPublicKey) GobEncode() ([]byte, error) {
	// Anonymous structure that flattens nested structures
	s := struct {
		P []byte
		Q []byte
		G []byte
		Y []byte
	}{
		p.key.Parameters.P.Bytes(),
		p.key.Parameters.Q.Bytes(),
		p.key.Parameters.G.Bytes(),
		p.key.Y.Bytes(),
	}

	var buf bytes.Buffer

	// Create new encoder that will transmit the buffer
	enc := gob.NewEncoder(&buf)

	// Transmit the data
	err := enc.Encode(s)

	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Overwrites the receiver, which must be a pointer, with DSAPublicKey
// represented by the byte slice, which was written by GobEncode().
func (p *DSAPublicKey) GobDecode(b []byte) error {
	// Anonymous, empty, flat structure
	s := struct {
		P []byte
		Q []byte
		G []byte
		X []byte
		Y []byte
	}{
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
	}

	var buf bytes.Buffer

	// Write bytes to the buffer
	buf.Write(b)

	// Create new decoder that reads from the buffer
	dec := gob.NewDecoder(&buf)

	// Receive and decode data
	err := dec.Decode(&s)

	if err != nil {
		return err
	}

	// Convert decoded bytes and put into empty structure
	p.key.Parameters.P = large.NewIntFromBytes(s.P).BigInt()
	p.key.Parameters.Q = large.NewIntFromBytes(s.Q).BigInt()
	p.key.Parameters.G = large.NewIntFromBytes(s.G).BigInt()
	p.key.Y = large.NewIntFromBytes(s.Y).BigInt()

	return nil
}

func (p *DSAPublicKey) Verify(hash []byte, sig DSASignature) bool {
	return dsa.Verify(&p.key, hash, sig.R.BigInt(), sig.S.BigInt())
}

func (p *DSAPublicKey) GetKey() large.Int {
	return large.NewIntFromBigInt(p.key.Y)
}

type DSASignature struct {
	R large.Int
	S large.Int
}
