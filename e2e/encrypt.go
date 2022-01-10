////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Packagee 2e contains functions used in the end-to-end encryption algorithm, including
// the end-to-end key rotation.
package e2e

import (
	"gitlab.com/elixxir/primitives/format"
	"golang.org/x/crypto/chacha20"
)

// Crypt uses XChaCha20 to encrypt or decrypt a message with the passed key using the
// fingerprint as a nonce
func Crypt(key Key, fingerprint format.Fingerprint, msg []byte) []byte {
	out := make([]byte, len(msg))
	nonce := fingerprint[:chacha20.NonceSizeX]
	cipher, err := chacha20.NewUnauthenticatedCipher(key[:], nonce)
	if err != nil {
		panic(err)
	}
	cipher.XORKeyStream(out, msg)
	// Return the result
	return out
}
