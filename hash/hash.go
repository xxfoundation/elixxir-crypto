/* Copyright 2020 xx network SEZC

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.

*/

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
)

// NewCMixHash returns the current cMix hash implementation
// which is currently the 256 bit version of blake2b
func NewCMixHash() (hash.Hash, error) {

	return blake2b.New256(nil)
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
