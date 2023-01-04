////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package dm

import (
	"bytes"
	"testing"

	"gitlab.com/elixxir/crypto/nike/ecdh"
	"gitlab.com/xx_network/crypto/csprng"
)

func TestScheme_EncryptSelf(t *testing.T) {
	message1 := []byte("i am a message")
	rng := csprng.NewSystemRNG()

	_, alicePubKey := ecdh.ECDHNIKE.NewKeypair(rng)
	bobPrivKey, _ := ecdh.ECDHNIKE.NewKeypair(rng)

	ciphertext, err := Cipher.EncryptSelf(message1, bobPrivKey,
		alicePubKey, 1024)
	if err != nil {
		t.Fatalf("Failed to encrypt: %+v", err)
	}

	if !Cipher.IsSelfEncrypted(ciphertext, bobPrivKey) {
		t.Fatalf("Not self encrypted")
	}

	pubKey, plaintext, err := Cipher.DecryptSelf(ciphertext, bobPrivKey)
	if err != nil {
		t.Fatalf("Failed to decrypt: %+v", err)
	}

	if !bytes.Equal(message1, plaintext) {
		t.Fatalf("Decrypted plaintext does not match originally encrypted message!")
	}

	if !bytes.Equal(pubKey.Bytes(), alicePubKey.Bytes()) {
		t.Fatalf("bad public keys: %s != %s", pubKey, alicePubKey)
	}

}
