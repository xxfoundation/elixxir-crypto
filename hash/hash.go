////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

// Package hash includes a general-purpose hashing algorithm, blake2b,
// that should be suitable for most of our needs.
// It also includes functions to calculate an HMAC.
package hash

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"golang.org/x/crypto/blake2b"
	"hash"
	"fmt"
)

// NewCMixHash returns the current cMix hash implementation
// which is currently the 256 bit version of blake2b
func NewCMixHash() (hash.Hash, error) {

	return blake2b.New256(nil)
}

// DefaultHash returns a CMIX hash or panics
func DefaultHash() hash.Hash {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(fmt.Sprintf("Could not initialize blake2b: %+v", err))
	}
	return h
}

// CMixHash type is currently BLAKE2b_256
var CMixHash = crypto.BLAKE2b_256

// NewHMAC creates a new Message Authentication Code from a message payload and a key.
// This function does not accept keys that are less than 256 bits (or 32 bytes)
// *Function was copied from (https://golang.org/pkg/crypto/hmac/), we need to analyze this again in the future *
func CreateHMAC(message, key []byte) []byte {

	h := hmac.New(sha256.New, key)
	h.Write(message)

	hMAC := h.Sum(nil)

	// blank out the first first bit in order to ensure the group is satisfied
	// in the message payload.  See primitives/format/message.go for more details
	hMAC[0] &= 0x7F

	return hMAC
}

// CheckHMAC receives a MAC value along with the respective message and key associated with the Msg Authentication Code
// Returns true if calculated MAC matches the received one. False if not.
// *Function was copied from (https://golang.org/pkg/crypto/hmac/), we need to analyze this again in the future *
func VerifyHMAC(message, MAC, key []byte) bool {
	expectedMAC := CreateHMAC(message, key)

	return hmac.Equal(MAC, expectedMAC)
}
