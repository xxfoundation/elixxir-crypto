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

// Package cmix derives new keys within the cyclic group from salts and a base key.
// It also is used for managing keys and salts for communication between clients
package cmix

import (
	"bytes"
	"gitlab.com/elixxir/crypto/cyclic"
	"hash"
)

// GenerateKMAC hashes the salt and base key together using the passed in hashing
// algorithm to produce a kmac
func GenerateKMAC(salt []byte, baseKey *cyclic.Int, h hash.Hash) []byte {
	h.Reset()
	h.Write(baseKey.Bytes())
	h.Write(salt)
	return h.Sum(nil)
}

// GenerateKMACs creates a list of KMACs all with the same salt but different
// base keys
func GenerateKMACs(salt []byte, baseKeys []*cyclic.Int, h hash.Hash) [][]byte {
	kmacs := make([][]byte, len(baseKeys))

	for i, baseKey := range baseKeys {
		kmacs[i] = GenerateKMAC(salt, baseKey, h)
	}

	return kmacs
}

// VerifyKMAC verifies that the generated GenerateKMAC is the same as the passed in GenerateKMAC
func VerifyKMAC(expectedKmac, salt []byte, baseKey *cyclic.Int, h hash.Hash) bool {
	//Generate KMAC based on the passed salt, key and hashing algorithm
	generated := GenerateKMAC(salt, baseKey, h)

	//Check that the kmacs are the same length
	if len(generated) != len(expectedKmac) {
		return false
	}

	//Check that the generated kmac matches the kmac passed in
	return bytes.Compare(expectedKmac, generated) == 0
}
