////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package rsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"gitlab.com/elixxir/crypto/hash"
	mathRand "math/rand"
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

// todo: do this
func TestPrivate_SignPSS_Consistency(t *testing.T) {

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

// Smoke test. Ensure that DecryptOAEP can decrypt the output from EncryptOAEP.
// Also ensure decryption returns original input to EncryptOAEP.
func TestEncryptDectyptOAEP(t *testing.T) {
	// Generate keys
	sLocal := GetScheme()
	rng := rand.Reader

	privKey, err := sLocal.GenerateDefault(rng)
	if err != nil {
		t.Errorf("GenerateDefault: %v", err)
	}

	pubKey := privKey.Public()

	// Generate encryption hashing functions
	hashFunc := hash.DefaultHash()

	for i := 0; i < numTest; i++ {
		// Construct encryption parameters
		data := []byte("hello user" + strconv.Itoa(i) + "!")
		label := []byte(strconv.Itoa(i + 1))

		// Encrypt data
		encrypted, err := pubKey.EncryptOAEP(hashFunc, rng, data, label)
		if err != nil {
			t.Fatalf("EncryptOAEP error: %+v", err)
		}

		// Decrypt data
		decrypted, err := privKey.DecryptOAEP(hashFunc, rng, encrypted, label)
		if err != nil {
			t.Fatalf("DecryptOAEP error: %+v", err)
		}

		// Check that decrypted text matches the original plaintext
		if !bytes.Equal(decrypted, data) {
			t.Fatalf("Decrypted data does not match original plaintext."+
				"\nExpected: %+v"+
				"\nReceived: %v", data, decrypted)
		}
	}
}

// Consistency test. Given pre-canned deterministic input to generate a
// PrivateKey, check that the output for EncryptOAEP is deterministic.
func TestPrivate_EncryptOAEP_Consistency(t *testing.T) {

	// Using a PRNG with same source so the output is the same on each run
	prng := mathRand.New(mathRand.NewSource(12))

	// Generate keys
	sLocal := GetScheme()

	privKey, err := sLocal.Generate(prng, 1024)
	if err != nil {
		t.Errorf("GenerateDefault: %v", err)
	}

	pubKey := privKey.Public()

	// Encryption hashing functions
	hashFunc := hash.DefaultHash()

	// Expected output
	expectedOutput := []string{
		"G8R1pxsm4tWReXrrAuPnjD07mr5Ke/KK1IOZfi++uhaz1GAef5TMskawb5htZtIEwciukYEZtQoSKWvuaDlfo3vAYeV0InS0PUrIb7jLaDGSnvkaArI7tULTcSOIUlbeoURMPH79bw2rNmrHvh72AaIRjbac/UE/V3192nWn+Ag=",
		"po/OQ5gDRvyzVKMEEwoQ97DEjly6LerFRN7SKcQqpto1bb4Kah6T2GmCvItOImbwV8dkOETZWws4QL7BHK0OiLvd3s9yZH7nesVIT3YZnd5vuO54v8iWhjTqpSqA/YOuuiEzQc1FoUt3F5+RDYIL/vKVJ4OfXGTiNXtdqOWCjUA=",
		"OMqTZfDAhyWppP9RruNNhFD1WxdCJrFO1lpr/xbuxEEui6U4YRjsubXy1xcLBgINoNTIAD7AeIRj1IgDArsLaDLghc3gIts6Ms8Q1TXHM8udIiF7cS61pOep7nlN9+ryuwJ6em1stOB4QEz54rqNMy6UGfXsRy54XbwrdIP6f8c=",
		"cR+IR238CxiepClSYd+vEQYPNQ2FNrzoLfVtSSarfN62VYAw5UtX5D76ucCZ2FOR7nFvj5O9v8NmOn1pEk8oIO+9QrxnC/XdkzI0DcLaz4kG/rssZGdVU/+alAMRW4vlOqKKxeU1DVpa/UdZZNLAndu/tu7yUa6s6ljc78Jehsw=",
		"mfYUhcUiCp2vICHeWEsYhHsHeAD5BVCNDUukJmAD91nbTRUevK4EY9eDIMgNG/6/+6cLfn4VWJ/x8ldMf8A4HF5ouTodXYBIsdDMNGvoB+sWVMgFfj41UtYkASyKdW30bZXiSK1WSlpvm9R99qtr8EbTIhTD1F3oiymeZ7ouwOI=",
	}
	for i := 0; i < numTest; i++ {

		// Construct plaintext
		plaintext := []byte("hello user" + strconv.Itoa(i) + "!")
		label := []byte(strconv.Itoa(i + 1))

		// Encrypt data
		encrypted, err := pubKey.EncryptOAEP(hashFunc, prng, plaintext, label)
		if err != nil {
			t.Fatalf("EncryptOAEP error: %+v", err)
		}

		// Check that encrypted data is consistent
		received := base64.StdEncoding.EncodeToString(encrypted)
		if expectedOutput[i] != received {
			t.Fatalf("EncryptOAEP did not produce consistent output with "+
				"precanned values."+
				"\nExpected: %s"+
				"\nReceived: %s", expectedOutput[i], received)
		}

	}

}

// Smoke test. Ensure that DecryptPKCS1v15 can decrypt the output from
// EncryptPKCS1v15. Also ensure decryption returns original input to
// EncryptPKCS1v15.
func TestEncryptDecryptPKCS1v15(t *testing.T) {
	sLocal := GetScheme()
	rng := rand.Reader

	// Construct keys
	privKey, err := sLocal.GenerateDefault(rng)
	if err != nil {
		t.Errorf("GenerateDefault: %v", err)
	}

	pubKey := privKey.Public()

	for i := 0; i < numTest; i++ {
		// Construct plaintext
		plaintext := []byte("hello user" + strconv.Itoa(i) + "!")

		// Encrypt data
		encrypted, err := pubKey.EncryptPKCS1v15(rng, plaintext)
		if err != nil {
			t.Fatalf("EncryptOAEP error: %+v", err)
		}

		// Decrypt data
		decrypted, err := privKey.DecryptPKCS1v15(rng, encrypted)
		if err != nil {
			t.Fatalf("DecryptOAEP error: %+v", err)
		}

		// Check that decrypted data matches the original plaintext.
		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("Decrypted plaintext does not match original plaintext."+
				"\nExpected: %+v"+
				"\nReceived: %v", plaintext, decrypted)
		}
	}

}
