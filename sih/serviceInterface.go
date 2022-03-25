package sih

import (
	"bytes"
	"crypto"
	"gitlab.com/elixxir/primitives/format"
)

var hasher = crypto.BLAKE2b_256.New

type Preimage [32]byte

type ServiceIdentification struct{
	Identifier []byte
	ServiceTag   string
	Source []byte //optional metadata field, only used on reception

	//private field for lazy evaluation of preimage
	preimage *Preimage
}

func (si ServiceIdentification)Hash(contents []byte)[]byte{
	preimage := si.Preimage()
	b2b := hasher()
	b2b.Write(GetMessageHash(contents))
	b2b.Write(preimage[:])
	return b2b.Sum(nil)[:format.SIHLen]
}

func (si ServiceIdentification)HashFromMessageHash(messageHash []byte)[]byte{
	preimage := si.Preimage()
	b2b := hasher()
	b2b.Write(messageHash)
	b2b.Write(preimage[:])
	return b2b.Sum(nil)[:format.SIHLen]
}

func (si ServiceIdentification)Preimage()Preimage{
	// dont recalculate if calculated before
	if si.preimage!=nil{
		return *si.preimage
	}

	var p Preimage
	si.preimage = &p

	if si.ServiceTag == Default {
		copy(p[:],si.Identifier)
		return *si.preimage
	}

	// Hash fingerprints
	h := hasher()
	h.Write(si.Identifier)
	h.Write([]byte(si.ServiceTag))

	pSlice := h.Sum(nil)

	copy(p[:],pSlice)

	// Base 64 encode hash and truncate
	return p
}

func (si ServiceIdentification)ForMe(contents, hash []byte)bool{
	return bytes.Equal(si.Hash(contents), hash)
}

func (si ServiceIdentification)ForMeFromMessageHash(messageHash, hash []byte)bool{
	return bytes.Equal(si.HashFromMessageHash(messageHash), hash)
}

func GetMessageHash(messagePayload []byte) []byte {
	b2b := hasher()
	b2b.Write(messagePayload)
	return b2b.Sum(nil)
}

