////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package auth

import (
	jww "github.com/spf13/jwalterweatherman"
	"golang.org/x/crypto/salsa20"
)

// Crypt Salsa20 encrypts or decrypts a message with the passed key and vector
func Crypt(key, vector, msg []byte) (crypt []byte) {
	// Bound check that the vector is long enough for Salsa20 encryption/decryption
	if len(vector) < VectorLen {
		jww.ERROR.Panicf("Vector is not of sufficient length for encryption/decryption")
	}

	out := make([]byte, len(msg))
	var keyArray [32]byte
	copy(keyArray[:], key)
	salsa20.XORKeyStream(out, msg, vector[:VectorLen], &keyArray)

	// Return the result
	return out
}
