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
// NOTE: This code assumes byte 0 is the Most significant byte (MSB)
func InGroup(sample, prime []byte) bool {
	// Absolute failure when it's empty or has more bits than prime
	if len(sample) == 0 || len(sample) > len(prime) {
		return false
	}

	// Check for a non-Zero byte
	isZero := true
	for i := 0; i < len(sample); i++ {
		if sample[i] != 0 {
			isZero = false
			break
		}
	}
	if isZero {
		return false
	}

	// If sample has less bits, then only needed to check for nonzero bytes
	if len(sample) < len(prime) {
		return true
	}

	// Else check that sample is strictly less than prime
	for i := 0; i < len(prime); i++ {
		if prime[i] > sample[i] {
			return true
		} else if prime[i] < sample[i] {
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

	primeLen := len(prime)
	//Reduce the size to prime length
	if size > primeLen {
		jww.WARN.Printf("Reducing size to match length of prime "+
			"(%d -> %d)", size, primeLen)
		size = primeLen
	}

	if primeLen > 0 && prime[0] == 0 {
		return nil, fmt.Errorf("prime must start with a non-zero byte")
	}

	// In the "slow" case for the InGroup call, generate aes BlockSize
	// chunks and iterate by byte until a byte is < the prime byte
	// at the same position.
	key := make([]byte, 0, size)
	genSize := size
	if size == primeLen && primeLen > aes.BlockSize {
		lessThan := false
		var rngBuf []byte
		rngIdx := 0
		primeIdx := 0
		for lessThan == false {
			// Edge Case: All bytes are == prime bytes
			// The prime is either very small OR unlucky RNG
			// NOTE: the case when all bytes generated are 0
			//       is avoided by requiring the first prime byte
			//       to be non-zero and only using this code
			//       when prime > aes.BlockSize
			if primeIdx >= primeLen {
				primeIdx = 0
				key = make([]byte, 0, size)
				continue
			}

			// Generate entropy when the buffer is empty
			if rngIdx >= len(rngBuf) {
				newBuf, err := Generate(aes.BlockSize, rng)
				if err != nil {
					return nil, err
				}
				if len(newBuf) <= 0 {
					e := fmt.Errorf("could not generate " +
						"more entropy")
					return nil, e
				}

				rngBuf = newBuf
				rngIdx = 0
			}

			cur := rngBuf[rngIdx]
			rngIdx++

			// Break out of loop if cur byte is less than the prime
			// byte at the same key location
			if cur < prime[primeIdx] {
				lessThan = true
			}

			// Add the byte to the key if it is <= the current prime
			// byte
			if cur <= prime[primeIdx] {
				key = append(key, cur)
				primeIdx++
			}
		}
		// NOTE: since prime[0] != 0, we cannot produce a stream
		// that is all 0's AND have len(key) == genSize or size because
		// it will exit in the first iteration (where it is known to be
		// < primeLen)
		if rngIdx < len(rngBuf) {
			key = append(key, rngBuf[rngIdx:len(rngBuf)]...)
			if len(key) > genSize {
				key = key[0:genSize]
			}
		}
		// Adjust the generate-able size for the rest of the bytes
		genSize -= len(key)
	}

	// Generate until we get something inside the prime group.
	// Note that InGroup is really only testing for non-zero if the "slow"
	// case above is triggered as len(rngValue) < primeLen
	for {
		rngValue, err := Generate(genSize, rng)
		// return if we get an error OR if we are in the group
		if err != nil || InGroup(rngValue, prime) {
			key = append(key, rngValue...)
			return key, err
		}
	}
}
