////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package rsa

import (
	"crypto"
	"crypto/rand"
	"strconv"
	"testing"
)

const numTest = 5

type CountingReader struct {
	count uint8
}

// Read just counts until 254 then starts over again
func (c *CountingReader) Read(b []byte) (int, error) {
	for i := 0; i < len(b); i++ {
		c.count = (c.count + 1) % 255
		b[i] = c.count
	}
	return len(b), nil
}

// Smoke test. Ensure that VerifyPSS can verify the output for SignPSS.
func TestSignVerifyPSS(t *testing.T) {
	// Generate keys
	sLocal := GetScheme()
	rng := rand.Reader

	privKey, err := sLocal.GenerateDefault(rng)
	if err != nil {
		t.Errorf("GenerateDefault: %v", err)
	}

	pubKey := privKey.Public()

	// Construct signing options
	opts := NewDefaultPSSOptions()
	hashFunc := opts.HashFunc()

	for i := 0; i < numTest; i++ {
		// Create hash
		h := hashFunc.New()
		h.Write([]byte(strconv.Itoa(i) + "test12345"))
		hashed := h.Sum(nil)

		// Construct signature
		signed, err := privKey.SignPSS(rng, hashFunc, hashed, opts)
		if err != nil {
			t.Fatalf("SignPSS error: %+v", err)
		}

		//Verify signature
		err = pubKey.VerifyPSS(hashFunc, hashed, signed, opts)
		if err != nil {
			t.Fatalf("VerifyPSS error: %+v", err)
		}
	}
}

// Smoke test. Ensure that VerifyPKCS1v15 can verify the output for
// SignPKCS1v15.
func TestPrivate_SignVerifyPKCS1v15(t *testing.T) {
	// Generate keys
	sLocal := GetScheme()
	rng := rand.Reader

	privKey, err := sLocal.GenerateDefault(rng)
	if err != nil {
		t.Errorf("GenerateDefault: %v", err)
	}

	pubKey := privKey.Public()

	// Construct signature hashing functions
	hashFunc := crypto.SHA256

	for i := 0; i < numTest; i++ {
		// Construct hash
		h := hashFunc.New()
		h.Write([]byte(strconv.Itoa(i) + "test12345"))
		hashed := h.Sum(nil)

		// Construct signature
		signed, err := privKey.SignPKCS1v15(rng, hashFunc, hashed)
		if err != nil {
			t.Fatalf("SignPKCS1v15 error: %+v", err)
		}

		// Verify signature
		err = pubKey.VerifyPKCS1v15(hashFunc, hashed, signed)
		if err != nil {
			t.Fatalf("VerifyPKCS1v15 error: %+v", err)
		}
	}
}
