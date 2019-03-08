package registration


import (
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
