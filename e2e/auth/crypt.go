////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package auth

import (
	"golang.org/x/crypto/salsa20"
)

// Crypt Salsa20 encrypts or decrypts a message with the passed key and vector
func Crypt(key, vector, msg []byte) []byte {
	out := make([]byte, len(msg))
	var keyArray [32]byte
	copy(keyArray[:], key)
	salsa20.XORKeyStream(out, msg, vector[:24], &keyArray)
	// Return the result
	return out
}
