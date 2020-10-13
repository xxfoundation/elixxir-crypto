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
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/hash"
)

// MakeMac returns the MAC for the given payload.
func MakeMac(pubkey *cyclic.Int, baseKey, salt, encryptedPayload []byte) []byte {
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.FATAL.Panicf("Could not get hash: %+v", err)
	}

	h.Write(pubkey.Bytes())
	h.Write(baseKey)
	h.Write(salt)
	h.Write(encryptedPayload)

	return h.Sum(nil)
}

// VerifyMac ensures that the provided MAC matches the provided payload
// information. Returns true if they match.
func VerifyMac(pubkey *cyclic.Int, baseKey, salt, encryptedPayload, mac []byte) bool {
	testMAC := MakeMac(pubkey, baseKey, salt, encryptedPayload)
	return bytes.Equal(mac, testMAC)
}
