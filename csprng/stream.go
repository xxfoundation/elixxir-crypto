////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

// Implementation of the Fortuna construction as specified by Feruson, Schnier and Kohno
// in 'Cryptography Engineering: Design Principles and Practical Applications'
// Link: https://www.schneier.com/academic/paperfiles/fortuna.pdf
package csprng

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	jww "github.com/spf13/jwalterweatherman/jwalterweatherman"
	"sync"
)

//Global hashing variable, used in the Fortuna construction
var newHash = sha256.New()

type StreamGenerator struct {
	AESCtr        cipher.Stream
	scalingFactor uint
	entropyCnt    uint
	rng           Source
	src           []byte
}

type Stream struct {
	streamGen *StreamGenerator
	mutex     sync.Mutex
}

/* Different ticket, put here for my convenience
// NewStreamGenerator creates a StreamGenerator object containing up to streamCount streams.
func NewStreamGenerator(source Source, scalingFactor uint, streamCount uint) *StreamGenerator{
	return &StreamGenerator
}
// GetStream gets an existing or creates a new Stream object. If the # of open streams exceeds streamCount,
// this function blocks (and prints a log warning) until a stream is available
func (*StreamGenerator) GetStream() *Stream{

}
// Close closes the stream object, locking it from external users and marking it as avaialble in the stream list
func (*RNGStreamGenerator) Close(*RNGStream)
*/

// Read reads up to len(b) bytes from the csprng.Source object. This function panics if the stream is locked.
// Users of stream objects should close them when they are finished using them. We read the AES256
// blocksize into AES then run it until blockSize*scalingFactor bytes are read. Every time
// blocksize*scalingFactor bytes are read this functions blocks until it rereads csprng.Source.
// TODO: Add 'blocking' logic, which is blocked by the ticket currently described above
func (s *Stream) Read(b []byte) int {
	//If the requested buffer exceeds the randomness generated thus far, then append until we have enough
	if len(b) > len(s.streamGen.src) {
		s.AppendSource(len(b))
	}

	//Read from source
	if s.streamGen.entropyCnt < uint(len(b)) {
		s.ReadFromSource(len(b))
	}
	//Make 'new randomness' by changing the values read through xor'ring
	s.streamGen.AESCtr.XORKeyStream(s.streamGen.src[:len(b)], b)

	return len(b)
}

// If the source is not large for the amount to be read in, extend the source
// using the Fortuna construction. Need a new block IV every
// In usage, src will initially pull from Linux's rng
func (s *Stream) AppendSource(lenToApp int) {
	//Initialize key and block
	key := make([]byte, 0)
	seedArr := append(key, s.streamGen.src...)
	key = newHash.Sum(seedArr)

	block, err := aes.NewCipher(key[:aes.BlockSize])
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, aes.BlockSize+len(key))
	var temp uint32 = 0
	counter := make([]byte, aes.BlockSize)
	for len(s.streamGen.src) < lenToApp {
		//Encrypt the key and counter, inc ctr for next round of generation
		binary.LittleEndian.PutUint32(counter, temp)
		stream := cipher.NewCTR(block, counter)
		stream.XORKeyStream(ciphertext[aes.BlockSize:], key)
		//So there is no predictable iv appended to the random src
		tmp := ciphertext[aes.BlockSize:]
		s.streamGen.src = append(s.streamGen.src, tmp...)
		temp++
	}
}

// Reads from source up to the length of b, factoring in the amount of entropy we have
func (s *Stream) ReadFromSource(lenOfB int) {
	//
	requiredRandomness := (uint(lenOfB) - s.streamGen.entropyCnt + s.streamGen.scalingFactor - 1) / s.streamGen.scalingFactor
	//Read from source up to that required randomness
	_, err := s.streamGen.rng.Read(s.streamGen.src[0:requiredRandomness])
	if err != nil {
		jww.ERROR.Printf(err.Error())
	}
	//
	s.streamGen.entropyCnt += requiredRandomness * s.streamGen.scalingFactor
}
