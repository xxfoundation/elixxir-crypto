////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package singleUse

import (
	"crypto/hmac"

	"gitlab.com/elixxir/crypto/hash"
)

const macSalt = "singleUseMacSalt"

// MakeMAC generates the MAC used in both the request and response cMix
// messages.
func MakeMAC(key []byte, encryptedPayload []byte) []byte {
	h := hmac.New(hash.DefaultHash, key)
	h.Write(encryptedPayload)
	h.Write([]byte(macSalt))
	mac := h.Sum(nil)

	// Set the first bit as zero to ensure everything stays in the group
	mac[0] &= 0b01111111

	return mac
}

// VerifyMAC determines if the provided MAC is valid for the given key and
// encrypted payload.
func VerifyMAC(key []byte, encryptedPayload, receivedMAC []byte) bool {
	newMAC := MakeMAC(key, encryptedPayload)

	return hmac.Equal(newMAC, receivedMAC)
}
