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
	testMessages := [][]byte{
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
	for _, inM := range testMessages {
		c, err2 := priv.EncryptOAEPMulticast(h, rng, inM, label)
		if err2 != nil {
			t.Fatalf("'%s': %+v", inM, err2)
		}

		m, err2 := pub.DecryptOAEPMulticast(h, c, label)
		if err2 != nil {
			t.Fatal(err2)
		}

		if !bytes.Equal(inM, m) {
			t.Errorf(
				"Encrypt/Decrypt mismatch.\nexected: %q\nreceived: %q", inM, m)
		}
	}
}

// Error path: tests that PrivateKey.EncryptOAEPMulticast returns the error
// ErrMessageTooLong when the message is too long.
func TestPrivateKey_EncryptOAEPMulticast_RSATooLong(t *testing.T) {
	tooLong := []byte("averylongmessageaverylongmessageaverylongkgeavery" +
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

	_, err = priv.EncryptOAEPMulticast(h, rng, tooLong, label)
	if err == nil || err != ErrMessageTooLong {
		t.Fatalf("Did not get expected error when the message should have "+
			"been too long to encrypt.\nexpected: %+v\nreceived: %+v",
			ErrMessageTooLong, err)
	}
}
