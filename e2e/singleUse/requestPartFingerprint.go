////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package singleUse

import (
	"encoding/binary"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/primitives/format"
)

const requestPartFpSalt = "singleUseRequestFingerprintSalt"

// NewRequestPartFingerprint generates the fingerprint for the request message
// for the given key number.
func NewRequestPartFingerprint(dhKey *cyclic.Int, keyNum uint64) format.Fingerprint {
	// Create new hash
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.FATAL.Panicf("[SU] Failed to create new hash for single-use "+
			"request fingerprint: %+v", err)
	}

	keyNumBytes := make([]byte, binary.MaxVarintLen64)
	binary.BigEndian.PutUint64(keyNumBytes, keyNum)

	// Hash the DH key, key number, and salt
	h.Write(dhKey.Bytes())
	h.Write(keyNumBytes)
	h.Write([]byte(requestPartFpSalt))

	// Get hash bytes
	fp := format.Fingerprint{}
	copy(fp[:], h.Sum(nil))

	// Set the first bit as zero to ensure everything stays in the group
	fp[0] &= 0b01111111

	return fp
}
