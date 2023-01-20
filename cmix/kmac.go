////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

// Package cmix derives new keys within the cyclic group from salts and a base key.
// It also is used for managing keys and salts for communication between clients
package cmix

import (
	"crypto/hmac"
	"encoding/binary"
	"hash"

	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/xx_network/primitives/id"
)

const kmacGenerationSalt = "cmixClientNodeKMACGenerationSalt"

// GenerateKMAC hashes the salt and base key together using the passed in hashing
// algorithm to produce a kmac
func GenerateKMAC(salt []byte, symmetricKey *cyclic.Int, roundID id.Round,
	h hash.Hash) []byte {

	// get the bytes of the roundID (monotonic counter)
	m := make([]byte, 8)
	binary.BigEndian.PutUint64(m, uint64(roundID))

	//generate the kmac
	h.Reset()
	h.Write(symmetricKey.Bytes())
	h.Write(salt)
	h.Write(m)
	h.Write([]byte(kmacGenerationSalt))
	return h.Sum(nil)
}

// GenerateKMACs creates a list of KMACs all with the same salt but different
// base keys
func GenerateKMACs(salt []byte, symmetricKeys []*cyclic.Int, roundID id.Round,
	h hash.Hash) [][]byte {
	kmacs := make([][]byte, len(symmetricKeys))

	for i, baseKey := range symmetricKeys {
		kmacs[i] = GenerateKMAC(salt, baseKey, roundID, h)
	}

	return kmacs
}

// VerifyKMAC verifies that the generated GenerateKMAC is the same as the passed in GenerateKMAC
func VerifyKMAC(expectedKmac, salt []byte, symmetricKey *cyclic.Int,
	roundID id.Round, h hash.Hash) bool {
	//Generate KMAC based on the passed salt, key and hashing algorithm
	generated := GenerateKMAC(salt, symmetricKey, roundID, h)

	//Check that the kmacs are the same length
	if len(generated) != len(expectedKmac) {
		return false
	}

	//Check that the generated kmac matches the kmac passed in
	return hmac.Equal(expectedKmac, generated)
}
