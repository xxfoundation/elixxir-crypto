package registration


import (
	"bufio"
	"bytes"
	"encoding/gob"
)

type EncoderDecoder interface {
	gob.GobEncoder
	gob.GobDecoder
}

type Parameters interface {
	ParametersMetadata() string
	EncoderDecoder
}

type PublicKey interface {
	PublicKeyMetadata() string
	EncoderDecoder
}

type PrivateKey interface {
	PrivateKeyMetadata() string
	EncoderDecoder
}

type Scheme interface {
	KeyGen(Parameters) (PublicKey, PrivateKey)
	Sign([]byte, PrivateKey) []byte
	Verify([]byte, PublicKey) bool
}

func decode(b []byte, e interface{}) error {
	reader := bufio.NewReader(b)

	dec := gob.NewDecoder(reader)

	return dec.Decode(e)
}

func encode(e interface{}) ([]byte, error) {
	var buffer bytes.Buffer

	enc := gob.NewEncoder(&buffer)

	err := enc.Encode(e)

	return buffer.Bytes(), err
}