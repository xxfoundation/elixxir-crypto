package signature

import (
	"bytes"
	"crypto/dsa"
	"encoding/asn1"
	"encoding/gob"
	"encoding/json"
	"encoding/pem"
	"errors"
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
	DSA_GROUP_P = "F6FAC7E480EE519354C058BF856AEBDC43AD60141BAD5573910476D030A869979A7E23F5FC006B6CE1B1D7CDA849BDE46A145F80EE97C21AA2154FA3A5CF25C75E225C6F3384D3C0C6BEF5061B87E8D583BEFDF790ECD351F6D2B645E26904DE3F8A9861CC3EAD0AA40BD7C09C1F5F655A9E7BA7986B92B73FD9A6A69F54EFC92AC7E21D15C9B85A76084D1EEFBC4781B91E231E9CE5F007BC75A8656CBD98E282671C08A5400C4E4D039DE5FD63AA89A618C5668256B12672C66082F0348B6204DD0ADE58532C967D055A5D2C34C43DF9998820B5DFC4C49C6820191CB3EC81062AA51E23CEEA9A37AB523B24C0E93B440FDC17A50B219AB0D373014C25EE8F"

	DSA_GROUP_Q = "D6B35AA395D9287A5530C474D776EA2FCF5B815E89C9DB4C7BB7A9EFB8F3F34B"

	DSA_GROUP_G = "B22FDF91EE6BA01BDE4969C1A986EA1F81C4A1795921403F3437D681D05E95167C2F6414CCB74AC8D6B3BA8C0E85C7E4DEB0E8B5256D37BC5C21C8BE068F5342858AFF2FC7FF2644EBED8B10271941C74C86CCD71AA6D2D98E4C8C70875044900F842998037A7DFB9BC63BAF1BC2800E73AF9615E4F5B869D4C6DE6E5F48FACE9CA594CC5D228CB7F763A0AD6BF6ED78B27F902D9ADA38A1FCD7D09E398CE377BB15A459044D3B8541DC6D8049B66AE1662682254E69FAD31CA0016251D0522EF8FE587A3F6E3AB1E5F9D8C2998874ABAB205217E95B234A7D3E69713B884918ADB57360B5DE97336C7DC2EB8A3FEFB0C4290E7A92FF5758529AC45273135427"
)

var ErrPemData = errors.New("failed to find PEM data in block containing public key")
var ErrPemType = errors.New("PEM block type incorrect; expected \"PUBLIC KEY\"")
var ErrPemDataPriv = errors.New("failed to find PEM data in block containing private key")
var ErrPemTypePriv = errors.New("PEM block type incorrect; expected \"PRIVATE KEY\"")

func GetDefaultDSAParams() *DSAParameters {
	bigP := large.NewIntFromString(DSA_GROUP_P, 16)
	bigQ := large.NewIntFromString(DSA_GROUP_Q, 16)
	bigG := large.NewIntFromString(DSA_GROUP_G, 16)
	jww.WARN.Printf("Using hardcoded DSA Params, should be removed in the future!")
	return CustomDSAParams(bigP, bigQ, bigG)
}

func CustomDSAParams(P, Q, G *large.Int) *DSAParameters {
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

func (p *DSAParameters) GetG() *large.Int {
	return large.NewIntFromBigInt(p.params.G)
}

func (p *DSAParameters) GetP() *large.Int {
	return large.NewIntFromBigInt(p.params.P)
}

func (p *DSAParameters) GetQ() *large.Int {
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

	var rval, sval *large.Int

	if err == nil {
		rval = large.NewIntFromBigInt(r)
		sval = large.NewIntFromBigInt(s)
	}

	return &DSASignature{rval, sval}, err
}

func (p *DSAPrivateKey) GetKey() *large.Int {
	return large.NewIntFromBigInt(p.key.X)
}

func ReconstructPrivateKey(publicKey *DSAPublicKey, privateKey *large.Int) *DSAPrivateKey {
	pk := &DSAPrivateKey{}

	pk.key.PublicKey = publicKey.key
	pk.key.X = privateKey.BigInt()

	return pk
}

type DSAPublicKey struct {
	key dsa.PublicKey
}

func ReconstructPublicKey(p *DSAParameters, key *large.Int) *DSAPublicKey {
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

// JsonEncode encodes the DSAPublicKey for JSON and return it, unless and error
// occurs.
func (p *DSAPublicKey) MarshalJSON() ([]byte, error) {
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

	// Encode the structure into JSON
	jsonData, err := json.Marshal(s)

	if err != nil {
		return nil, err
	}

	return jsonData, nil
}

// JsonDecode decodes JSON data into a DSAPublicKey and returns it.
func (p *DSAPublicKey) UnmarshalJSON(b []byte) (*DSAPublicKey, error) {
	// Anonymous, empty, flat structure
	s := struct {
		P []byte
		Q []byte
		G []byte
		Y []byte
	}{
		[]byte{},
		[]byte{},
		[]byte{},
		[]byte{},
	}

	// Decode the JSON to a temporary structure
	err := json.Unmarshal(b, &s)

	if err != nil {
		return nil, err
	}

	// Convert decoded bytes and put into structure
	p.key.Parameters.P = large.NewIntFromBytes(s.P).BigInt()
	p.key.Parameters.Q = large.NewIntFromBytes(s.Q).BigInt()
	p.key.Parameters.G = large.NewIntFromBytes(s.G).BigInt()
	p.key.Y = large.NewIntFromBytes(s.Y).BigInt()

	return p, nil
}

func (p *DSAPublicKey) Verify(hash []byte, sig DSASignature) bool {
	return dsa.Verify(&p.key, hash, sig.R.BigInt(), sig.S.BigInt())
}

func (p *DSAPublicKey) GetKey() *large.Int {
	return large.NewIntFromBigInt(p.key.Y)
}

type DSASignature struct {
	R *large.Int
	S *large.Int
}

// PemEncode returns the PEM encoding of the DSAPublicKey key.
func (p *DSAPublicKey) PemEncode() ([]byte, error) {

	// Encode the public key to ASN.1
	asn1Bytes, err := asn1.Marshal(p.key)
	if err != nil {
		return nil, err
	}

	// Represents the PEM encoded structure
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	return pem.EncodeToMemory(block), nil
}

// PemDecode returns the PEM encoding of the DSAPublicKey key.
func (p *DSAPublicKey) PemDecode(pemBytes []byte) (*DSAPublicKey, error) {

	// Decode the public key from the PEM encoded structure block
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrPemData
	} else if block.Type != "PUBLIC KEY" {
		return nil, ErrPemType
	}

	// Decode the ASN.1 key to the dsa.PublicKey
	_, err := asn1.Unmarshal(block.Bytes, &p.key)
	if err != nil {
		return nil, err
	}

	// Construct the DSAPublicKey structure and return it
	return p, nil
}

func (p *DSAPrivateKey) PemEncode() ([]byte, error) {
	asn1Bytes, err := asn1.Marshal(p.key)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: asn1Bytes,
	}

	return pem.EncodeToMemory(block), nil
}

func (p *DSAPrivateKey) PemDecode(pemBytes []byte) (*DSAPrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrPemDataPriv
	} else if block.Type != "PRIVATE KEY" {
		return nil, ErrPemTypePriv
	}

	//Decode the ASN.1 key to the dsa.PrivateKey
	_, err := asn1.Unmarshal(block.Bytes, &p.key)
	if err != nil {
		return nil, err
	}

	return p, nil

}
