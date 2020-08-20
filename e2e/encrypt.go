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
	"golang.org/x/crypto/salsa20"
)

// CryptUnsafe Salsa20 encrypts or decrypts a message with the passed key using the
// fingerprint as a nonce
// DOES NOT PAD message, so this could be unsafe if message is too small
func CryptUnsafe(key Key, fingerprint format.Fingerprint, msg []byte) []byte {
	out := make([]byte, len(msg))
	keyArray := [32]byte(key)
	salsa20.XORKeyStream(out, msg, fingerprint[:24], &keyArray)
	// Return the result
	return out
}

// Encrypt encrypts a message by first padding it, using rand.Reader and then
// encrypts the payload with salsa20.
// encLen is the length of the payload after padding
func Encrypt(key Key, fingerprint format.Fingerprint, msg []byte, encLen int) ([]byte, error) {
	// Get the padded message
	encMsg, err := Pad(msg, encLen)

	// Return if an error occurred
	if err != nil {
		return nil, err
	}
	return CryptUnsafe(key, fingerprint, encMsg), nil
}

// Encrypt decrypts the payload with salsa20 and then unpads it
func Decrypt(key Key, fingerprint format.Fingerprint, encMsg []byte) ([]byte, error) {
	decMsg := CryptUnsafe(key, fingerprint, encMsg)

	// Remove the padding from the message
	unPadMsg, err := Unpad(decMsg)

	// Return if an error occurred
	if err != nil {
		return nil, err
	}
	return unPadMsg, nil
}
