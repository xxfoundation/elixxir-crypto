////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package csprng

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
)

// SystemRNG uses the golang CSPRNG
type SystemRNG struct{}

//Gets the systemRNG as the interface
func NewSystemRNG() Source {
	return &SystemRNG{}
}

// Read calls the crypto/rand Read function and returns the values
func (s *SystemRNG) Read(b []byte) (int, error) {
	return rand.Read(b)
}

// SetSeed has not effect on the system reader
func (s *SystemRNG) SetSeed(seed []byte) error {
	return nil
}

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
	//Generate more randomness, if we are requesting more than exists right now
	if len(b) > len(s.streamGen.src) {
		s.streamGen.src = AppendSource(len(b), s.streamGen.src)
	}

	//Read from source up to required randomness
	if s.streamGen.entropyCnt < uint(len(b)) {
		requiredRandomness := (uint(len(b)) - s.streamGen.entropyCnt + s.streamGen.scalingFactor - 1) / s.streamGen.scalingFactor

		_, err := s.streamGen.rng.Read(s.streamGen.src[0:requiredRandomness])
		if err != nil {
			fmt.Println(err.Error())
		}

		s.streamGen.entropyCnt += requiredRandomness * s.streamGen.scalingFactor
	}
	//Make 'new randomness' by changing the values read through xor'ring
	s.streamGen.AESCtr.XORKeyStream(s.streamGen.src[:len(b)], b)

	return len(b)
}

// If the source is not large for the amount to be read in, extend the source
// using the Fortuna construction. Need a new block IV every
// In usage, src will partially pull from Linux's rng
func AppendSource(lenToApp int, src []byte) []byte {
	//Initialize key and block
	key := make([]byte, 0)
	seedArr := append(key, src...)
	key = sha256.New().Sum(seedArr)
	block, err := aes.NewCipher(key[:aes.BlockSize])
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(key))
	var temp uint32 = 0
	counter := make([]byte, aes.BlockSize)
	for len(src) < lenToApp {
		//Encrypt the key and counter, inc ctr for next round of generation
		binary.LittleEndian.PutUint32(counter, temp)
		stream := cipher.NewCTR(block, counter)
		stream.XORKeyStream(ciphertext[aes.BlockSize:], key)
		//So there is no predictable iv appended to the random src
		tmp := ciphertext[aes.BlockSize:]
		src = append(src, tmp...)
		temp++
	}
	return src
}
