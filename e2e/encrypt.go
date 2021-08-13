////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Packagee 2e contains functions used in the end-to-end encryption algorithm, including
// the end-to-end key rotation.
package e2e

import (
	"git.xx.network/elixxir/primitives/format"
	"golang.org/x/crypto/salsa20"
)

// CryptUnsafe Salsa20 encrypts or decrypts a message with the passed key using the
// Crypt Salsa20 encrypts or decrypts a message with the passed key using the
// fingerprint as a nonce
func Crypt(key Key, fingerprint format.Fingerprint, msg []byte) []byte {
	out := make([]byte, len(msg))
	keyArray := [32]byte(key)
	salsa20.XORKeyStream(out, msg, fingerprint[:24], &keyArray)
	// Return the result
	return out
}
