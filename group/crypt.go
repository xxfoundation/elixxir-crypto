////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// The internal message format for group messaging is encrypted using XChaCha20
// with the group key and key fingerprint.

package group

import (
	"gitlab.com/elixxir/crypto/e2e/auth"
	"gitlab.com/elixxir/primitives/format"
)

// Encrypt encrypts the internal message with XChaCha20.
func Encrypt(key CryptKey, keyFingerprint format.Fingerprint, internalMsg []byte) []byte {
	return auth.Crypt(key[:], keyFingerprint.Bytes(), internalMsg)
}

// Decrypt decrypts the encrypted internal message with XChaCha20.
func Decrypt(key CryptKey, keyFingerprint format.Fingerprint, encryptedInternalMsg []byte) []byte {
	return auth.Crypt(key[:], keyFingerprint.Bytes(), encryptedInternalMsg)
}
