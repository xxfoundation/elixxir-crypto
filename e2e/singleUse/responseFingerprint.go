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
	"git.xx.network/elixxir/crypto/cyclic"
	"git.xx.network/elixxir/crypto/hash"
	"git.xx.network/elixxir/primitives/format"
)

const responseFpSalt = "singleUseResponseFingerprintSalt"

// NewResponseFingerprint generates the fingerprint for the response message for
// the given key number.
func NewResponseFingerprint(dhKey *cyclic.Int, keyNum uint64) format.Fingerprint {
	// Create new hash
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.ERROR.Panicf("Failed to create new hash for single-use response "+
			"fingerprint: %v", err)
	}

	keyNumBytes := make([]byte, binary.MaxVarintLen64)
	binary.BigEndian.PutUint64(keyNumBytes, keyNum)

	// Hash the DH key, key number, and salt
	h.Write(dhKey.Bytes())
	h.Write(keyNumBytes)
	h.Write([]byte(responseFpSalt))

	// Get hash bytes
	fp := format.Fingerprint{}
	copy(fp[:], h.Sum(nil))

	// Set the first bit as zero to ensure everything stays in the group
	fp[0] &= 0b01111111

	return fp
}
