////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package csprng

// Source is the common interface for all cryptographically secure random number
// generators
type Source interface {
	// Read returns a slice of size bytes from the random number generator, or
	// an error if one occurs
	Read(size int) ([]byte, error)
	// SetSeed sets the internal state of the random number generator, or an error
	SetSeed(seed []byte) error
}
