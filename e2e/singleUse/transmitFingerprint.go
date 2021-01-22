////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                           //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file                                                               //
////////////////////////////////////////////////////////////////////////////////

package singleUse

import (
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/primitives/format"
)

const transmitFPConstant = "transmitFPConstant"

// TransmitFingerprint generates the fingerprint used for the transmission
// message.
func TransmitFingerprint(dhKey *cyclic.Int) format.Fingerprint {
	// Create fingerprint
	fp := format.NewFingerprint(makeHash(dhKey, []byte(transmitFPConstant)))

	// Set the first bit as zero to ensure everything stays in the group
	fp[0] &= 0b01111111

	return fp
}
