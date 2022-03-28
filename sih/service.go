package sih

import (
	"bytes"
	"crypto"
	"gitlab.com/elixxir/primitives/format"
)

var hasher = crypto.BLAKE2b_256.New

type Preimage [32]byte

func Hash(preimage Preimage, contents []byte)[]byte{
	b2b := hasher()
	b2b.Write(GetMessageHash(contents))
	b2b.Write(preimage[:])
	return b2b.Sum(nil)[:format.SIHLen]
}

func HashFromMessageHash(preimage Preimage, messageHash []byte)[]byte{
	b2b := hasher()
	b2b.Write(messageHash)
	b2b.Write(preimage[:])
	return b2b.Sum(nil)[:format.SIHLen]
}

func MakePreimage(identifier []byte, tag string)Preimage{

	var p Preimage

	if tag == Default {
		copy(p[:],identifier)
		return p
	}

	// Hash fingerprints
	h := hasher()
	h.Write(identifier)
	h.Write([]byte(tag))

	pSlice := h.Sum(nil)

	copy(p[:],pSlice)

	return p
}

func ForMe(preimage Preimage, contents, hash []byte)bool{
	return bytes.Equal(Hash(preimage, contents), hash)
}

func ForMeFromMessageHash(preimage Preimage, messageHash, hash []byte)bool{
	return bytes.Equal(HashFromMessageHash(preimage, messageHash), hash)
}

func GetMessageHash(messagePayload []byte) []byte {
	b2b := hasher()
	b2b.Write(messagePayload)
	return b2b.Sum(nil)
}

