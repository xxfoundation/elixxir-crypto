////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                           //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file                                                               //
////////////////////////////////////////////////////////////////////////////////

package singleUse

import (
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/primitives/format"
)

const requestFpSalt = "singleUseTransmitFingerprintSalt"

// NewRequestFingerprint generates the fingerprint used for the request message.
func NewRequestFingerprint(pubKey *cyclic.Int) format.Fingerprint {
	// Create new hash
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.FATAL.Panicf("[SU] Failed to create new hash for single-use "+
			"request fingerprint: %+v", err)
	}

	// Hash the public key and salt
	h.Write(pubKey.Bytes())
	h.Write([]byte(requestFpSalt))

	// Get hash bytes
	fp := format.Fingerprint{}
	copy(fp[:], h.Sum(nil))

	// Set the first bit as zero to ensure everything stays in the group
	fp[0] &= 0b01111111

	return fp
}
