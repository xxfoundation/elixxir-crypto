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
	"runtime"
	"strconv"
	"testing"
)

const numTest = 5

// Smoke test: ensure that PublicKey.VerifyPSS can verify the output for
// PrivateKey.SignPSS.
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

	// Javascript only uses SHA-256
	if runtime.GOOS == "js" {
		opts.Hash = crypto.SHA256
		hashFunc = opts.HashFunc()
		t.Log("Javascript environment; using SHA-256.")
	}

	for i := 0; i < numTest; i++ {
		// Create hash
		h := hashFunc.New()
		h.Write([]byte(strconv.Itoa(i) + "test12345"))
		hashed := h.Sum(nil)

		// Construct signature
		signed, err2 := privKey.SignPSS(rng, hashFunc, hashed, opts)
		if err2 != nil {
			t.Fatalf("SignPSS error: %+v", err2)
		}

		// Verify signature
		err = pubKey.(*public).VerifyPSS(hashFunc, hashed, signed, opts)
		if err != nil {
			t.Fatalf("VerifyPSS error: %+v", err)
		}
	}
}

// Smoke test: ensure that PublicKey.VerifyPKCS1v15 can verify the output for
// PrivateKey.SignPKCS1v15.
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
		signed, err2 := privKey.SignPKCS1v15(rng, hashFunc, hashed)
		if err2 != nil {
			t.Fatalf("SignPKCS1v15 error: %+v", err2)
		}

		// Verify signature
		err = pubKey.VerifyPKCS1v15(hashFunc, hashed, signed)
		if err != nil {
			t.Fatalf("VerifyPKCS1v15 error: %+v", err)
		}
	}
}
