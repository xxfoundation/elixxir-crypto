///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package singleUse

import (
	"encoding/binary"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/primitives/format"
)

const responseFPConstant = "responseFPConstant"

// ResponseFingerprint generates the fingerprint for the response message for
// the given key number.
func ResponseFingerprint(dhKey *cyclic.Int, keyNum uint64) format.Fingerprint {
	// Create fingerprint
	fp := format.NewFingerprint(makeKeyHash(dhKey, keyNum, responseFPConstant))

	// Set the first bit as zero to ensure everything stays in the group
	fp[0] &= 0b01111111

	return fp
}

// makeHash generates a hash from the given key and list of bytes.
func makeHash(key *cyclic.Int, data ...[]byte) []byte {
	// Create new hash
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.ERROR.Panicf("Failed to create new hash for single-use "+
			"communication: %v", err)
	}

	// Hash the key and data
	h.Write(key.Bytes())
	for _, d := range data {
		h.Write(d)
	}

	return h.Sum(nil)
}

// makeKeyHash generates a hash from a key, an integer, and a string.
func makeKeyHash(dhKey *cyclic.Int, keyNum uint64, constant string) []byte {
	// Convert the key number to bytes
	keyNumBytes := make([]byte, binary.MaxVarintLen64)
	binary.BigEndian.PutUint64(keyNumBytes, keyNum)

	return makeHash(dhKey, keyNumBytes, []byte(constant))
}
