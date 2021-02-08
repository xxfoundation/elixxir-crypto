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

const transmitFpSalt = "singleUseTransmitFingerprintSalt"

// NewTransmitFingerprint generates the fingerprint used for the transmission
// message.
func NewTransmitFingerprint(pubKey *cyclic.Int) format.Fingerprint {
	// Create new hash
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.ERROR.Panicf("Failed to create new hash for single-use "+
			"transmission fingerprint: %v", err)
	}

	// Hash the public key and salt
	h.Write(pubKey.Bytes())
	h.Write([]byte(transmitFpSalt))

	// Get hash bytes
	fp := format.Fingerprint{}
	copy(fp[:], h.Sum(nil))

	// Set the first bit as zero to ensure everything stays in the group
	fp[0] &= 0b01111111

	return fp
}
