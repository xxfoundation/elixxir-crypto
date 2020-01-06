////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

// Package csprng wraps the golang crypto/rand package so that we can use different
// random number generators interchangeably when the need arises.
package csprng

import (
	"crypto/aes"
	"fmt"
	jww "github.com/spf13/jwalterweatherman"
	"io"
)

//Defines the constructor of a source
type SourceConstructor func() Source

// Source is the common interface for all cryptographically secure random number
// generators
type Source interface {
	// Read returns a slice of len(b) size bytes from the random number
	// generator, or an error if one occurs
	Read(b []byte) (int, error)
	// SetSeed sets the internal state of the random number generator, or an error
	SetSeed(seed []byte) error
}

// InGroup returns true if the sample is non-zero and less than
// the prime. This is useful for testing if a generated number is
// inside the modular cyclic group defined by the prime.
// NOTE: This code assumes byte 0 is the MSB.
func InGroup(sample, prime []byte) bool {
	if len(sample) == 0 || len(sample) > len(prime) {
		return false
	}

	if len(sample) == 1 && sample[0] == 0 {
		return false
	}

	if len(sample) < len(prime) {
		return true
	}

	for i := 0; i < len(sample); i++ {
		if prime[i] > sample[i] {
			return true
		} else if sample[i] > prime[i] {
			return false
		}
	}
	return false
}

// Generate a byte slice of size and return the result
// Note use of io.Reader interface, as Source implements that, we only
// require a Read function for these utilities.
func Generate(size int, rng io.Reader) ([]byte, error) {
	key := make([]byte, size)
	byteCount, err := rng.Read(key)
	if err == nil && byteCount != size {
		err = fmt.Errorf("Generated %d bytes, not %d as requested!",
			byteCount, size)
	}
	return key, err
}

// GenerateInGroup creates a byte slice of at most size inside the given prime
// group and returns the result
func GenerateInGroup(prime []byte, size int, rng io.Reader) ([]byte,
	error) {

	//Reduce the size to prime length
	if size > len(prime) {
		jww.WARN.Printf("Reducing size to match length of prime "+
			"(%d -> %d)", size, len(prime))
		size = len(prime)
	}

	//If we are generating a random byte slice that is shorter than prime, then it will always be in group
	if size < len(prime) || len(prime) < aes.BlockSize {
		for {
			key, err := Generate(size, rng)
			// return if we get an error OR if we are in the group
			if err != nil || InGroup(key, prime) {
				return key, err
			}
		}
	}

	//Otherwise, we need to generate blockSize chunks and compare to the prime
	key := make([]byte, 0, size)
	for block := 0; block < size/aes.BlockSize; {
		//Generate an rand value of AES Block size
		rngValue := make([]byte, aes.BlockSize)
		rngValue, err := Generate(aes.BlockSize, rng)
		if err != nil {
			return nil, err
		}
		//We only need the first block's value to be in the group of the corresponding prime block
		if block == 0 {
			if InGroup(rngValue, prime[block*aes.BlockSize:(block+1)*aes.BlockSize]) {
				block++
				key = append(key, rngValue...)

			}
			//After the first block just append the rngVal to the key, as it will be in group
		} else {
			block++
			key = append(key, rngValue...)

		}

	}
	//If prime is not AES block aligned, generate the remaining bytes of randomness as needed
	if len(key) < len(prime) {
		rngPad := make([]byte, len(prime)-len(key))
		rngPad, err := Generate(len(rngPad), rng)
		if err != nil {
			return nil, err
		}
		key = append(key, rngPad...)
	}

	return key, nil
}
