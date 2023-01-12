////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

//go:build js && wasm

package rsa

import (
	"crypto"
	"crypto/rand"
	gorsa "crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"strconv"
	"testing"
)

// Smoke test: ensure that the Go implementation of PublicKey.VerifyPSS can
// verify the output for the Javascript implementation of PrivateKey.SignPSS.
func Test_SignJS_VerifyGo_PSS(t *testing.T) {
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
	opts.Hash = crypto.SHA256
	hashFunc := opts.HashFunc()
	opts.SaltLength = 32

	for i := 0; i < numTest; i++ {
		// Create hash
		dataToSign := []byte(strconv.Itoa(i) + "test12345")
		h := hashFunc.New()
		h.Write(dataToSign)
		hashed := h.Sum(nil)

		// Construct signature
		signed, err2 := privKey.SignPSS(rng, hashFunc, dataToSign, opts)
		if err2 != nil {
			t.Fatalf("SignPSS error: %+v", err2)
		}

		salt := make([]byte, 32)
		if _, err := io.ReadFull(rng, salt); err != nil {
			t.Fatal(err)
		}

		// Verify signature
		err = gorsa.VerifyPSS(
			pubKey.GetGoRSA(), hashFunc, hashed, signed, &opts.PSSOptions)
		if err != nil {
			t.Fatalf("VerifyPSS error: %+v", err)
		}
	}
}

// Smoke test: ensure that the Go implementation of PublicKey.VerifyPSS can
// verify the output for the Javascript implementation of PrivateKey.SignPSS.
// This test uses a private key generated in Go using a key size that is not a
// multiple of 128 and imported into Go.
func Test_SignJS_VerifyGo_PSS_Non128MultipleKeySize(t *testing.T) {
	// Generate keys
	sLocal := GetScheme()
	rng := rand.Reader

	goPrivKey, err := gorsa.GenerateKey(rng, 1032)
	if err != nil {
		t.Errorf("GenerateDefault: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(goPrivKey)})

	privKey, err := sLocal.UnmarshalPrivateKeyPEM(pemBytes)
	if err != nil {
		t.Errorf("GenerateDefault: %v", err)
	}

	pubKey := privKey.Public()

	// Construct signing options
	opts := NewDefaultPSSOptions()
	opts.Hash = crypto.SHA256
	hashFunc := opts.HashFunc()
	opts.SaltLength = 32

	for i := 0; i < numTest; i++ {
		// Create hash
		dataToSign := []byte(strconv.Itoa(i) + "test12345")
		h := hashFunc.New()
		h.Write(dataToSign)
		hashed := h.Sum(nil)

		// Construct signature
		signed, err2 := privKey.SignPSS(rng, hashFunc, dataToSign, opts)
		if err2 != nil {
			t.Fatalf("SignPSS error: %+v", err2)
		}

		salt := make([]byte, 32)
		if _, err := io.ReadFull(rng, salt); err != nil {
			t.Fatal(err)
		}

		// Verify signature
		err = gorsa.VerifyPSS(
			pubKey.GetGoRSA(), hashFunc, hashed, signed, &opts.PSSOptions)
		if err != nil {
			t.Fatalf("VerifyPSS error: %+v", err)
		}
	}
}

// Smoke test: ensure that the Javascript implementation of PublicKey.VerifyPSS
// can verify the output for the Go implementation of PrivateKey.SignPSS.
func Test_SignGo_VerifyJS_PSS(t *testing.T) {
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
	opts.Hash = crypto.SHA256
	hashFunc := opts.HashFunc()

	for i := 0; i < numTest; i++ {
		// Create hash
		h := hashFunc.New()
		dataToSign := []byte(strconv.Itoa(i) + "test12345")
		h.Write(dataToSign)
		hashed := h.Sum(nil)

		// Construct signature
		signed, err2 := gorsa.SignPSS(
			rng, privKey.GetGoRSA(), hashFunc, hashed, &opts.PSSOptions)
		if err2 != nil {
			t.Fatalf("SignPSS error: %+v", err2)
		}

		// Verify signature
		err = pubKey.(*public).VerifyPSS(hashFunc, dataToSign, signed, opts)
		if err != nil {
			t.Fatalf("VerifyPSS error: %+v", err)
		}
	}
}

// Smoke test: ensure that the Go implementation PublicKey.VerifyPKCS1v15 can
// verify the output for the Javascript implementation PrivateKey.SignPKCS1v15.
func Test_SignGo_VerifyJS_PKCS1v152(t *testing.T) {
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
		dataToSign := []byte(strconv.Itoa(i) + "test12345")
		h.Write(dataToSign)
		hashed := h.Sum(nil)

		// Construct signature
		signed, err2 := privKey.SignPKCS1v15(rng, hashFunc, dataToSign)
		if err2 != nil {
			t.Fatalf("SignPKCS1v15 error: %+v", err2)
		}

		// Verify signature
		err = gorsa.VerifyPKCS1v15(pubKey.GetGoRSA(), hashFunc, hashed, signed)
		if err != nil {
			t.Fatalf("VerifyPKCS1v15 error: %+v", err)
		}
	}
}

// Smoke test: ensure that the Javascript implementation
// PublicKey.VerifyPKCS1v15 can verify the output for the Go implementation
// PrivateKey.SignPKCS1v15.
func Test_SignJS_VerifyGO_PKCS1v152(t *testing.T) {
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
		dataToSign := []byte(strconv.Itoa(i) + "test12345")
		h.Write(dataToSign)
		hashed := h.Sum(nil)

		// Construct signature
		signed, err2 := gorsa.SignPKCS1v15(
			rng, privKey.GetGoRSA(), hashFunc, hashed)
		if err2 != nil {
			t.Fatalf("SignPKCS1v15 error: %+v", err2)
		}

		// Verify signature
		err = pubKey.VerifyPKCS1v15(hashFunc, dataToSign, signed)
		if err != nil {
			t.Fatalf("VerifyPKCS1v15 error: %+v", err)
		}
	}
}
