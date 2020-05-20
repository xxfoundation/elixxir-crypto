////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

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
	// Check that sample's len is smaller than primes
	if len(sample) == 0 || len(sample) > len(prime) {
		return false
	}

	// Check that sample is not simply 0
	if len(sample) == 1 && sample[0] == 0 {
		return false
	}

	if len(sample) < len(prime) {
		return true
	}

	// Check that the sample is strictly less than the prime
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

	// In the "slow" case for the InGroup call, generate aes BlockSize
	// chunks until one of them is zero or inside the most significant bytes
	// of the prime group.
	key := make([]byte, 0, size)
	genSize := size
	if size == len(prime) && len(prime) >= aes.BlockSize {
		// Reduce the generate size in the second half of the code block
		genSize -= aes.BlockSize
		var firstBlock []byte
		for firstBlock == nil {
			rngValue, err := Generate(aes.BlockSize, rng)
			if err != nil {
				return nil, err
			}

			if InGroup(rngValue, prime[0:aes.BlockSize]) {
				firstBlock = rngValue
				continue
			}

			// Check if the block is 0
			zero := true
			for i := 0; i < aes.BlockSize; i++ {
				if rngValue[i] != 0 {
					zero = false
					break
				}
			}
			if zero {
				firstBlock = rngValue
			}
		}
		key = append(key, firstBlock...)
	}

	// Generate until we get something inside the prime group.
	// Note that InGroup is really only testing for non-zero if the "slow"
	// case above is triggered as len(rngValue) < len(prime)
	for {
		rngValue, err := Generate(genSize, rng)
		// return if we get an error OR if we are in the group
		if err != nil || InGroup(rngValue, prime) {
			key = append(key, rngValue...)
			return key, err
		}
	}
}
