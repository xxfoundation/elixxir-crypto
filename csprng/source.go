////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package csprng

import (
	"fmt"
	jww "github.com/spf13/jwalterweatherman"
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
	// Absolute failure when it's got more bits than prime
	if len(sample) > len(prime) {
		return false
	}

	// If sample has less bits, then only check for nonzero bytes
	if len(sample) < len(prime) {
		for i := 0; i < len(sample); i++ {
			if sample[i] != 0 {
				return true
			}
		}
		return false
	}

	// Else check for both
	notZero := false
	lessThan := false
	for i := 0; i < len(prime); i++ {
		if notZero == false && sample[i] != 0 {
			notZero = true
		}
		if lessThan == false && prime[i] > sample[i] {
			lessThan = true
		}
		if lessThan == true && notZero == true {
			return true
		}
	}
	return false
}

// Generate a byte slice of size and return the result
func Generate(size int, rng Source) ([]byte, error) {
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
func GenerateInGroup(prime []byte, size int, rng Source) ([]byte,
	error) {
	if size > len(prime) {
		jww.WARN.Printf("Reducing size to match length of prime "+
			"(%d -> %d)", size, len(prime))
		size = len(prime)
	}
	for {
		key, err := Generate(size, rng)
		// return if we get an error OR if we are in the group
		if err != nil || InGroup(key, prime) {
			return key, err
		}
		jww.INFO.Printf("Failed to generate key in group. If this" +
			" message repeats, check for RNG issues...")
	}
}
