////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package auth

import (
	jww "github.com/spf13/jwalterweatherman"
	"golang.org/x/crypto/chacha20"
)

// Required length of the nonce within XChaCha20
const NonceLength = chacha20.NonceSizeX

// Crypt XChaCha20 encrypts or decrypts a message with the passed key and vector
func Crypt(key, vector, msg []byte) (crypt []byte) {
	// Bound check that the vector is long enough for XChaCha20 encryption/decryption
	if len(vector) < NonceLength {
		jww.ERROR.Panicf("Vector is not of sufficient length for encryption/decryption")
	}

	out := make([]byte, len(msg))
	nonce := vector[:NonceLength]

	cipher, err := chacha20.NewUnauthenticatedCipher(key[:], nonce)
	if err != nil {
		panic(err)
	}
	cipher.XORKeyStream(out, msg)

	// Return the result
	return out
}
