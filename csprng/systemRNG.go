////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package csprng

import (
	"crypto/rand"
)

// SystemRNG uses the golang CSPRNG
type SystemRNG struct{}

// Read calls the crypto/rand Read function and returns the values
func (s *SystemRNG) Read(b []byte) (int, error) {
	return rand.Read(b)
}

// SetSeed has not effect on the system reader
func (s *SystemRNG) SetSeed(seed []byte) error {
	return nil
}
