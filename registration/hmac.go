////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package registration

import (
	"bytes"
	"hash"
)

// This file contains logic constructing MACs related to any registration code path.

// CreateClientHMAC constructs an HMAC on the encrypted client key.
func CreateClientHMAC(sessionKey, encryptedKey []byte,
	h hash.Hash) []byte {
	// Construct H(SessionKey, EncryptedClientKey)
	h.Reset()
	h.Write(sessionKey)
	h.Write(encryptedKey)
	hashedData := h.Sum(nil)
	h.Reset()

	// Construct HMAC
	h.Write(sessionKey)
	h.Write(hashedData)
	encryptedClientKeyHMAC := h.Sum(nil)

	return encryptedClientKeyHMAC
}

// VerifyClientHMAC checks if the hmac received matches the values received.
func VerifyClientHMAC(sessionKey, encryptedKey []byte,
	h hash.Hash, receivedHmac []byte) bool {

	expectedHmac := CreateClientHMAC(sessionKey, encryptedKey, h)
	return bytes.Equal(receivedHmac, expectedHmac)
}
