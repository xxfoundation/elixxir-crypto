////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package broadcast

import (
	"crypto/hmac"

	"gitlab.com/elixxir/crypto/hash"
)

// makeMAC returns the MAC for the given payload. It is an HMAC with proper H
// padding and O padding.
func makeMAC(key, encryptedPayload []byte) []byte {
	h := hmac.New(hash.DefaultHash, key)
	h.Write(encryptedPayload)
	sum := h.Sum(nil)

	// Set the first bit as zero to ensure everything stays in the group
	sum[0] &= 0x7F

	return sum
}

// verifyMAC ensures that the provided MAC matches the provided payload and key.
// Returns true if they match.
func verifyMAC(key, encryptedPayload, mac []byte) bool {
	testMAC := makeMAC(key, encryptedPayload)
	return hmac.Equal(mac, testMAC)
}
