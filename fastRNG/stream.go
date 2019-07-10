////////////////////////////////////////////////////////////////////////////////
// Copyright © 2019 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

// Implementation of the Fortuna construction as specified by Ferguson, Schnier and Kohno
// in 'Cryptography Engineering: Design Principles and Practical Applications'
// Link: https://www.schneier.com/academic/paperfiles/fortuna.pdf
package fastRNG

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/csprng"
	"sync"
)


type StreamGenerator struct {
	scalingFactor uint
}

type Stream struct {
	streamGen *StreamGenerator
	mutex     sync.Mutex
	src           []byte
	entropyCnt    uint
	AESCtr        cipher.Stream
	rng           csprng.Source
}

// Read reads up to len(b) bytes from the csprng.Source object. This function panics if the stream is locked.
// Users of stream objects should close them when they are finished using them. We read the AES256
// blocksize into AES then run it until blockSize*scalingFactor bytes are read. Every time
// blocksize*scalingFactor bytes are read this functions blocks until it rereads csprng.Source.
// TODO: Add 'blocking' logic, which is blocked by the ticket currently described above
func (s *Stream) Read(b []byte) int {
	//s.mutex.Lock()
	//If the requested buffer exceeds the randomness generated thus far, then append until we have enough
	if len(b) > len(s.src) {
		s.extendSource(len(b))
	}

	//Read from source
	if requiredRandomness := s.getEntropyNeeded(uint(len(b))); requiredRandomness != 0 {
		_, err := s.rng.Read(s.src[0:requiredRandomness])
		if err != nil {
			jww.ERROR.Printf(err.Error())
		}

		s.SetEntropyCount(uint(len(b)))
	}

	//
	s.entropyCnt -= uint(len(b))
	//Make 'new randomness' by changing the stale values (already read data read through xor'ring
	//We may also just as easily retire the read values. This is up to discussion?
	s.AESCtr.XORKeyStream(s.src[:len(b)], b)
	//s.mutex.Unlock()
	return len(b)
}

// If the source is not large for the amount to be read in, extend the source
// using the Fortuna construction. Need a new block IV every
// In usage, src will initially pull from Linux's rng
func (s *Stream) extendSource(extensionLen int) {
	//Initialize key and block
	var fortunaHash = crypto.SHA256
	key := fortunaHash.New().Sum(s.src)
	key = key[len(s.src):]

	block, err := aes.NewCipher(key[:aes.BlockSize])
	if err != nil {
		jww.ERROR.Println(err)
	}
	//Make sure the key is the key size (32 bytes), panic otherwise
	if len(key) != 32 {
		panic("The key is not the correct length (ie not 32 bytes)!")
	}
	aesRngBuf := make([]byte, aes.BlockSize+len(key))
	var temp uint16 = 0
	counter := make([]byte, aes.BlockSize)
	//Encrypt the key and counter, inc ctr for next round of generation
	for len(s.src) < extensionLen {
		//Increment the temp, place in the counter. When the temp var overflows, the 1 is carried over to the next byte
		//in counter, treating it like a binary number. Counter is used as the IV
		binary.LittleEndian.PutUint16(counter, temp)
		stream := cipher.NewCTR(block, counter)
		stream.XORKeyStream(aesRngBuf[aes.BlockSize:], key)
		//So there is no predictable iv appended to the random src
		tmp := aesRngBuf[aes.BlockSize:]
		s.src = append(s.src, tmp...)
		temp++
	}
}

// TODO: test this function
// Sets the required randomness, ie the amount we will read from source by factoring in the amount of entropy we
// actually have and the sources of entropy we have.
func (s *Stream) getEntropyNeeded(requestLen uint) uint {
	//Such that the return value is never negative (requestedLen - entropyCnt) would be negative
	// if entropyCnt > requestedLen
	if s.entropyCnt >= requestLen {
		return 0
	}

	//The addition (scalingFactor - 1) ensures that the returned value is always a ceiling rather than a floor
	//as an integer. e.g ceiling(a/b) = (a+b-1)/b
	return (requestLen - s.entropyCnt + s.streamGen.scalingFactor - 1) / s.streamGen.scalingFactor
}

// Increases the entropy by a factor of the requestedLen
//
func (s *Stream) SetEntropyCount(requestedLen uint) {
	s.entropyCnt += requestedLen * s.streamGen.scalingFactor
}
