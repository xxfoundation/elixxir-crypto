////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// The MAC for the encrypted internal format proves the authenticity of the
// message and sender.

package group

import (
	"bytes"
	"gitlab.com/elixxir/crypto/cyclic"
	"golang.org/x/crypto/blake2b"
)

// NewMAC generates a MAC for the encrypted internal message and the recipient's
// Diffie–Hellman key.
func NewMAC(key CryptKey, encryptedInternalMsg []byte, recipientDhKey *cyclic.Int) []byte {
	// Hash the key, the encrypted message, and DH key
	h, _ := blake2b.New256(nil)
	h.Write(key[:])
	h.Write(encryptedInternalMsg)
	h.Write(recipientDhKey.Bytes())

	mac := h.Sum(nil)

	// Set the first bit to be 0 to comply with the group requirements in the
	// cMix message format.
	mac[0] &= 0x7F

	return mac
}

// CheckMAC verifies that the given MAC matches the provided data.
func CheckMAC(mac []byte, key CryptKey, encryptedInternalMsg []byte,
	recipientDhKey *cyclic.Int) bool {

	return bytes.Equal(mac, NewMAC(key, encryptedInternalMsg, recipientDhKey))
}
