package signature


import (
	"bufio"
	"bytes"
	"encoding/gob"
)

type EncoderDecoder interface {
	Name() string
	gob.GobEncoder
	gob.GobDecoder
}


type NewParameters func(...interface{})Parameters

type Parameters interface {
	PrivateKeyGen(...interface{}) PrivateKey
	EncoderDecoder
}

type PrivateKey interface {
	PublicKeyGen(...interface{}) PublicKey
	Sign([]byte, ...interface{})(interface{},error)
	EncoderDecoder
}

type PublicKey interface {
	Verify([]byte)bool
	EncoderDecoder
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