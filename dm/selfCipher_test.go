////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package dm

import (
	"bytes"
	"gitlab.com/elixxir/crypto/nike/ecdh"
	"testing"
)

func TestScheme_EncryptSelf(t *testing.T) {
	message1 := []byte("i am a message")

	//alicePrivKey, _ := ecdh.ECDHNIKE.NewKeypair()
	bobPrivKey, _ := ecdh.ECDHNIKE.NewKeypair()

	ciphertext, err := Cipher.EncryptSelf(message1, bobPrivKey, 1024)
	if err != nil {
		t.Fatalf("Failed to encrypt: %+v", err)
	}
	
	plaintext, err := Cipher.DecryptSelf(ciphertext, bobPrivKey)
	if err != nil {
		t.Fatalf("Failed to decrypt: %+v", err)
	}

	if !bytes.Equal(message1, plaintext) {
		t.Fatalf("Decrypted plaintext does not match originally encrypted message!")
	}

}