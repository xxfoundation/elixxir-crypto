///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

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
