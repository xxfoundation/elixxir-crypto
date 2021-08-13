////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// The internal message format for group messaging is encrypted using Salsa20
// with the group key and key fingerprint.

package group

import (
	"git.xx.network/elixxir/crypto/e2e/auth"
	"git.xx.network/elixxir/primitives/format"
)

// Encrypt encrypts the internal message with Salsa20.
func Encrypt(key CryptKey, keyFingerprint format.Fingerprint, internalMsg []byte) []byte {
	return auth.Crypt(key[:], keyFingerprint.Bytes(), internalMsg)
}

// Decrypt decrypts the encrypted internal message with Salsa20.
func Decrypt(key CryptKey, keyFingerprint format.Fingerprint, encryptedInternalMsg []byte) []byte {
	return auth.Crypt(key[:], keyFingerprint.Bytes(), encryptedInternalMsg)
}
