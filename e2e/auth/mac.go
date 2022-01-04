////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package auth

// To create authenticated channels between users, a user must create and verify
// a message authentication code (MAC). The MAC is appended to the initial
// channel payload.

import (
	"bytes"
	"gitlab.com/elixxir/crypto/hash"
)

// MakeMac returns the MAC for the given payload.
func MakeMac(baseKey, encryptedPayload []byte) []byte {
	//suppress because we just panic and a nil hash will panic anyhow
	h, _ := hash.NewCMixHash()
	// This will panic if we got an error in the line above, but does nothing
	// if it worked.
	h.Reset()

	h.Write(baseKey)
	h.Write(encryptedPayload)

	sum := h.Sum(nil)
	// The first bit must be 0.
	sum[0] &= 0x7F

	return sum
}

// VerifyMac ensures that the provided MAC matches the provided payload
// information. Returns true if they match.
func VerifyMac(baseKey, encryptedPayload, mac []byte) bool {
	testMAC := MakeMac(baseKey, encryptedPayload)
	return bytes.Equal(mac, testMAC)
}
