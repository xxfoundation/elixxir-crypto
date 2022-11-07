////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package group

import (
	"bytes"
	"gitlab.com/elixxir/primitives/format"
	"math/rand"
	"testing"
)

// Tests that data that is encrypted and decrypted match the original.
func TestEncryptDecrypt(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	var key CryptKey
	prng.Read(key[:])
	var keyFingerprint format.Fingerprint
	prng.Read(keyFingerprint[:])
	internalMsg := make([]byte, 1024)
	prng.Read(internalMsg)

	encryptedData := Encrypt(key, keyFingerprint, internalMsg)

	decryptedData := Decrypt(key, keyFingerprint, encryptedData)

	if !bytes.Equal(internalMsg, decryptedData) {
		t.Errorf("Failed to encrypt and decrypt message."+
			"\nexpected: %+v\nreceived: %+v", internalMsg, decryptedData)
	}
}
