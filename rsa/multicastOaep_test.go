////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found         //
// in the LICENSE file.                                                       //
// NOTE: This code is largely copied from golang's crypto/rsa pcakge, so it   //
//       is 3-clause and not 2-clause BSD. Unchanged code (excepting type     //
//       modifications) is noted at the bottom of this file.                  //
////////////////////////////////////////////////////////////////////////////////

// oaep_test.go implements basic testing for broadcast RSA

package rsa

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func TestEncryptDecryptRSA(t *testing.T) {
	test_messages := [][]byte{
		[]byte("Hello"),
		[]byte("World!"),
		[]byte("How"),
		[]byte("Are"),
		[]byte("You"),
		[]byte(""), // Empty test
		[]byte("averylongmessageaverylongmessageaverylongmessageavery"),
		[]byte("This is a short little message to test it."),
	}

	sLocal := GetScheme()

	priv, err := sLocal.Generate(rand.Reader, 1024)
	if err != nil {
		t.Errorf("Failed to generate private key: %+v", err)
	}
	pub := priv.Public()

	h := sha256.New()
	label := []byte("testing123")
	rng := rand.Reader

	// Encrypt, then decrypt and check each message
	for i := 0; i < len(test_messages); i++ {
		inM := test_messages[i]
		c, err := priv.EncryptOAEPMulticast(h, rng, inM, label)
		if err != nil {
			t.Fatalf("'%s': %+v", inM, err)
		}

		m, err := pub.DecryptOAEPMulticast(h, c, label)
		if err != nil {
			t.Fatalf("%+v", err)
		}

		if bytes.Compare(inM, m) != 0 {
			t.Errorf("Encrypt/Decrypt Mismatch, in: %v, out: %v",
				inM, m)
		}
	}
}

func TestEncryptRSATooLong(t *testing.T) {
	too_long := []byte("averylongmessageaverylongmessageaverylongkgeavery" +
		"longmessageaverylongmessageaverylongmessageaverylong" +
		"longmessageaverylongmessageaverylongmessageaverylong" +
		"longmessageaverylongmessageaverylongmessageaverylong" +
		"messageaverngmessage") // will not fit

	sLocal := GetScheme()

	priv, err := sLocal.Generate(rand.Reader, 1024)
	if err != nil {
		t.Errorf("Failed to generate private key: %+v", err)
	}

	h := sha256.New()
	label := []byte("testing123")
	rng := rand.Reader

	inM := too_long
	_, err = priv.EncryptOAEPMulticast(h, rng, inM, label)
	if err == nil {
		t.Fatalf("Message should have been too long to encrypt!")
	}
}
