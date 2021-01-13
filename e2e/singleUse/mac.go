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
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/hash"
)

const macConstant = "macConstant"

// MakeMAC generates the MAC for the given base key and encrypted payload.
func MakeMAC(baseKey *cyclic.Int, encryptedPayload []byte) []byte {
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.ERROR.Panicf("Failed to create hash: %v", err)
	}

	// Hash the key, number, and constant
	h.Write(baseKey.Bytes())
	h.Write(encryptedPayload)
	h.Write([]byte(macConstant))

	return h.Sum(nil)
}

// VerifyMAC determines if the provided MAC is valid for the given base key and
// encrypted payload.
func VerifyMAC(baseKey *cyclic.Int, encryptedPayload, receivedMAC []byte) bool {
	newMAC := MakeMAC(baseKey, encryptedPayload)

	return bytes.Equal(newMAC, receivedMAC)
}
