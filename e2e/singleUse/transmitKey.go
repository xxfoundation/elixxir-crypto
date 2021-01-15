///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package singleUse

import (
	"gitlab.com/elixxir/crypto/cyclic"
)

const transmitKeyConstant = "transmitKeyConstant"

// TransmitFingerprint generates the key used for the transmission message.
func TransmitKey(dhKey *cyclic.Int) []byte {
	return makeHash(dhKey, []byte(transmitKeyConstant))
}
