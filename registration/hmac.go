////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package registration

import (
	"crypto/hmac"
	"hash"
)

// This file contains logic constructing MACs related to any registration code path.

// CreateClientHMAC constructs an HMAC on the encrypted client key.
func CreateClientHMAC(sessionKey, encryptedKey []byte,
	h func() hash.Hash) []byte {

	mac := hmac.New(h, sessionKey)
	mac.Write(encryptedKey)
	encryptedClientKeyHMAC := mac.Sum(nil)

	return encryptedClientKeyHMAC
}

// VerifyClientHMAC checks if the hmac received matches the values received.
func VerifyClientHMAC(sessionKey, encryptedKey []byte,
	h func() hash.Hash, receivedHmac []byte) bool {

	expectedHmac := CreateClientHMAC(sessionKey, encryptedKey, h)
	return hmac.Equal(receivedHmac, expectedHmac)
}
