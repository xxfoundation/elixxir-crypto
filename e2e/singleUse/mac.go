///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package singleUse

import (
	"bytes"
	"gitlab.com/elixxir/crypto/cyclic"
)

const macConstant = "macConstant"

// MakeMAC generates the MAC used in the cmix message holding the single-use
// payload.
func MakeMAC(dhKey *cyclic.Int, encryptedPayload []byte) []byte {
	mac := makeHash(dhKey, encryptedPayload, []byte(macConstant))

	// Set the first bit as zero to ensure everything stays in the group
	mac[0] &= 0b01111111

	return mac
}

// VerifyMAC determines if the provided MAC is valid for the given key and
// encrypted payload.
func VerifyMAC(dhKey *cyclic.Int, encryptedPayload, receivedMAC []byte) bool {
	newMAC := MakeMAC(dhKey, encryptedPayload)

	return bytes.Equal(newMAC, receivedMAC)
}
