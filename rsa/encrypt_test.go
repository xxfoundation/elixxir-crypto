////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package rsa

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"gitlab.com/elixxir/crypto/hash"
	rand2 "math/rand"
	"runtime"
	"strconv"
	"testing"
)

// Smoke test: ensure that PrivateKey.DecryptOAEP can decrypt the output from
// PublicKey.EncryptOAEP. Also ensures decryption returns original input to
// PublicKey.EncryptOAEP.
func TestPublicKey_EncryptOAEP_PrivateKey_DecryptOAEP(t *testing.T) {
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
				"\nexpected: %v\nreceived: %v", data, decrypted)
		}
	}
}

var privateKeyPem = []byte{45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 82, 83,
	65, 32, 80, 82, 73, 86, 65, 84, 69, 32, 75, 69, 89, 45, 45, 45, 45, 45,
	10, 77, 73, 73, 67, 87, 119, 73, 66, 65, 65, 75, 66, 103, 81, 67, 116, 67,
	68, 86, 85, 76, 80, 119, 79, 107, 47, 86, 106, 65, 105, 74, 102, 48, 57,
	51, 83, 43, 72, 107, 121, 84, 103, 75, 117, 68, 47, 56, 52, 77, 82, 99,
	65, 107, 79, 112, 75, 69, 117, 116, 82, 119, 87, 80, 69, 10, 53, 117, 101,
	73, 113, 47, 103, 79, 110, 88, 99, 50, 102, 84, 48, 52, 51, 70, 106, 102,
	111, 103, 82, 99, 57, 77, 119, 49, 89, 85, 98, 83, 103, 71, 119, 115, 86,
	82, 85, 89, 51, 100, 65, 102, 47, 75, 51, 76, 87, 120, 77, 50, 117, 49,
	108, 106, 56, 72, 122, 49, 122, 75, 72, 84, 10, 100, 120, 114, 113, 107,
	72, 47, 69, 103, 116, 121, 47, 121, 66, 114, 112, 104, 73, 114, 56, 52, 114,
	83, 117, 77, 104, 86, 113, 54, 120, 112, 104, 71, 101, 102, 100, 68, 109,
	56, 110, 111, 81, 101, 78, 115, 109, 107, 97, 103, 66, 89, 82, 90, 47, 117,
	82, 86, 119, 73, 68, 65, 81, 65, 66, 10, 65, 111, 71, 65, 72, 104, 97, 68,
	84, 51, 80, 84, 69, 75, 88, 104, 48, 97, 109, 90, 87, 74, 104, 54, 120, 105,
	105, 50, 121, 109, 121, 79, 81, 114, 52, 57, 88, 119, 81, 75, 80, 43, 114,
	122, 69, 112, 90, 102, 110, 81, 80, 72, 50, 89, 70, 100, 87, 89, 75, 116,
	121, 55, 122, 78, 10, 56, 103, 101, 116, 69, 97, 111, 102, 79, 105, 80, 117,
	74, 107, 118, 98, 66, 112, 48, 51, 116, 51, 114, 108, 86, 68, 98, 118, 76,
	109, 87, 114, 54, 114, 90, 81, 120, 87, 120, 71, 74, 82, 88, 103, 110, 79,
	72, 47, 108, 102, 121, 121, 52, 54, 90, 98, 114, 66, 51, 101, 112, 85, 51,
	103, 10, 72, 111, 82, 56, 51, 47, 65, 107, 112, 100, 88, 117, 83, 115, 114,
	76, 51, 69, 115, 114, 43, 65, 65, 85, 116, 101, 79, 43, 85, 85, 78, 89, 50,
	98, 48, 84, 99, 121, 99, 88, 47, 43, 114, 99, 68, 69, 69, 67, 81, 81, 68, 78,
	78, 102, 82, 69, 81, 116, 88, 121, 71, 101, 86, 88, 10, 55, 100, 53, 75, 71,
	101, 106, 65, 105, 65, 121, 83, 66, 113, 105, 83, 103, 68, 99, 97, 119, 82,
	71, 90, 76, 86, 77, 100, 118, 70, 66, 97, 111, 71, 98, 104, 89, 90, 110,
	107, 77, 90, 113, 65, 72, 102, 80, 65, 77, 99, 116, 43, 116, 120, 66, 43,
	55, 52, 74, 53, 118, 56, 73, 80, 10, 103, 65, 78, 83, 49, 98, 115, 80, 65,
	107, 69, 65, 49, 57, 116, 116, 48, 68, 106, 110, 51, 107, 112, 80, 55, 100,
	119, 86, 68, 77, 65, 117, 49, 48, 73, 90, 66, 113, 90, 78, 82, 54, 81, 85,
	106, 48, 113, 50, 108, 100, 70, 75, 109, 75, 53, 52, 104, 101, 112, 122,
	110, 48, 110, 108, 10, 48, 118, 56, 57, 110, 87, 79, 119, 118, 99, 116, 47,
	43, 47, 50, 48, 121, 120, 68, 85, 117, 97, 115, 77, 76, 48, 101, 105, 65,
	117, 104, 108, 79, 81, 74, 65, 67, 55, 104, 99, 74, 104, 88, 110, 73, 68,
	101, 111, 97, 74, 103, 50, 84, 79, 99, 106, 54, 118, 77, 97, 80, 76, 68, 83,
	10, 113, 101, 78, 87, 119, 108, 108, 113, 104, 117, 81, 87, 122, 105, 106,
	50, 77, 101, 98, 100, 87, 86, 118, 52, 114, 82, 98, 69, 75, 122, 77, 75,
	117, 57, 120, 99, 77, 102, 87, 69, 112, 75, 116, 76, 79, 87, 98, 104, 84,
	51, 57, 82, 77, 85, 98, 120, 115, 119, 74, 65, 84, 110, 112, 116, 10, 115,
	49, 49, 116, 70, 52, 108, 110, 65, 47, 67, 88, 67, 112, 113, 52, 114, 80,
	82, 81, 67, 118, 88, 100, 100, 79, 86, 51, 119, 66, 48, 71, 119, 118, 78,
	106, 114, 112, 48, 73, 72, 111, 47, 57, 49, 51, 84, 84, 104, 79, 72, 100,
	99, 101, 74, 122, 117, 74, 49, 75, 43, 55, 47, 105, 10, 119, 107, 49, 116,
	79, 99, 43, 120, 84, 50, 77, 52, 121, 78, 118, 98, 75, 81, 74, 65, 67, 82,
	69, 66, 98, 100, 110, 81, 70, 74, 48, 76, 106, 117, 75, 103, 76, 77, 49, 99,
	89, 78, 108, 107, 111, 99, 67, 57, 56, 78, 84, 85, 75, 119, 73, 77, 106, 49,
	83, 50, 79, 113, 115, 70, 10, 55, 107, 101, 43, 103, 43, 121, 100, 74, 89,
	100, 102, 78, 56, 76, 100, 54, 49, 56, 100, 100, 48, 111, 82, 122, 47, 119,
	111, 48, 118, 116, 100, 120, 112, 102, 117, 101, 116, 52, 116, 113, 81, 61,
	61, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 82, 83, 65, 32, 80, 82, 73, 86,
	65, 84, 69, 32, 75, 69, 89, 45, 45, 45, 45, 45}

// Consistency test: given pre-canned deterministic input to generate a
// PrivateKey, check that the output for PublicKey.EncryptOAEP is deterministic.
func TestPrivateKey_PublicKey_EncryptOAEP_Consistency(t *testing.T) {
	// Cannot run consistency test when running in Javascript
	if runtime.GOOS == "js" {
		t.Log("Javascript environment; skipping this test.")
		return
	}

	// Using a PRNG with same source so the output is the same on each run
	prng := rand2.New(rand2.NewSource(12))

	// Generate keys
	sLocal := GetScheme()

	privKey, err := sLocal.UnmarshalPrivateKeyPEM(privateKeyPem)
	if err != nil {
		t.Errorf("GenerateDefault: %v", err)
	}
	pubKey := privKey.Public()

	// Encryption hashing functions
	hashFunc := hash.DefaultHash()

	// Expected output
	expectedOutput := []string{
		"BAqF9cxQARWZKfSnMLQLUoxHGcH6OdCopfggl8W17sK6i+4AAfevZVXeiPLZsaL4KKRN" +
			"MKF/4IRT6Pneulvy56HicvI6oFoKSvMq+KoFEXpHl8PVqY/tIZltZEvsL/GVQaXv" +
			"Ixa4okvG95EHzFyUidNMC36zia8ITqt/OH1aNWc=",
		"U/GmLIgGceD1PQjm/1y68CZrG8HvoDJvGH/P3dMf5jBNige0Z85MIPjHE4jgbn0wJNuU" +
			"cJP7l5+ANLQOVjLhysKLvXo81oyLtR42TRJdiO7/gsExE2cbL28aTuDc662k+VDh" +
			"JwmGknvCfQ0yyzFa2ZsLf5sWQdoX97fgpDdW5Bw=",
		"EFzf7zuJU5UYx8zIl8jJcQI5xz2arjwYxTkXeTou9UTSQtHOy4LLfHJUqq5UAc0isV1y" +
			"+RIqGoKImuIDL39u7iiDVgGt70Bn6gmputx4sc0NuiYAD70sLzGmZ89O15DuoxnU" +
			"d60NhrdVvvxzZ7dMhpX/ZQAQCaaVfyt2Mvot2U4=",
		"jAD2VtmHtYdnMBsfrVJ4EKlmz0/z09GSYm2i6UaIFUo3ynTpIiPDBVaaDa5mzNTJtkcC" +
			"OC+SvNiKbpfzNzRRkK1qGyCWFHsUjW+c4brWTw+c0QCX/Sg3ENpKD+DdNH/FfZPe" +
			"9KE23GQUdh6ljc3N2TO86VNv1KYmfcA3HelaO+E=",
		"K2yQM8KfPb2+p73vPqoeHng/tlNKhrEkhFydmF8rDfkJ/EUC309bavMnesKD2SZmlC2v" +
			"bjrlvQz3VUuf6Ig5LrAiBk5eV/QjDt1wCHHEz0jOErGPMfJWc0TZYxgNhkrT3ufe" +
			"azklxvL/ieM1cxzqxKudOiWrzIj0O/3lasaa3WM=",
	}

	for i, expected := range expectedOutput {
		// Construct plaintext
		plaintext := []byte("hello user" + strconv.Itoa(i) + "!")
		label := []byte(strconv.Itoa(i + 1))

		// Encrypt data
		encrypted, err2 := pubKey.EncryptOAEP(hashFunc, prng, plaintext, label)
		if err2 != nil {
			t.Errorf("EncryptOAEP error: %+v", err2)
		}

		// Check that encrypted data is consistent
		received := base64.StdEncoding.EncodeToString(encrypted)
		if expected != received {
			t.Errorf("EncryptOAEP did not produce consistent output with "+
				"precanned values.\nexpected: %s\nreceived: %s",
				expected, received)
		}
	}
}

// Smoke test: ensure that PrivateKey.DecryptPKCS1v15 can decrypt the output
// from PublicKey.EncryptPKCS1v15. Also ensure decryption returns original input
// to PublicKey.EncryptPKCS1v15.
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
		encrypted, err2 := pubKey.EncryptPKCS1v15(rng, plaintext)
		if err2 != nil {
			t.Fatalf("EncryptOAEP error: %+v", err2)
		}

		// Decrypt data
		decrypted, err2 := privKey.DecryptPKCS1v15(rng, encrypted)
		if err2 != nil {
			t.Fatalf("DecryptOAEP error: %+v", err2)
		}

		// Check that decrypted data matches the original plaintext.
		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("Decrypted plaintext does not match original plaintext."+
				"\nexpected: %v\nreceived: %v", plaintext, decrypted)
		}
	}
}
