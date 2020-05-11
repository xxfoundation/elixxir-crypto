////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Package csprng wraps the golang crypto/rand package so that we can use different
// random number generators interchangeably when the need arises.
package csprng

import (
	"crypto/rand"
)

// SystemRNG uses the golang CSPRNG
type SystemRNG struct{}

// NewSystemRNG gets the systemRNG as the interface
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
