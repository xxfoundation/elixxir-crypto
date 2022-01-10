///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package singleUse

import (
	"bytes"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/hash"
)

const macSalt = "singleUseMacSalt"

// MakeMAC generates the MAC used in both the transmission and response CMIX
// messages.
func MakeMAC(key []byte, encryptedPayload []byte) []byte {
	// Create new hash
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.ERROR.Panicf("Failed to create new hash for single-use MAC: %v", err)
	}

	// Hash the key, encrypted payload, and salt
	h.Write(key)
	h.Write(encryptedPayload)
	h.Write([]byte(macSalt))

	// Get hash bytes
	mac := h.Sum(nil)

	// Set the first bit as zero to ensure everything stays in the group
	mac[0] &= 0b01111111

	return mac
}

// VerifyMAC determines if the provided MAC is valid for the given key and
// encrypted payload.
func VerifyMAC(key []byte, encryptedPayload, receivedMAC []byte) bool {
	newMAC := MakeMAC(key, encryptedPayload)

	return bytes.Equal(newMAC, receivedMAC)
}
