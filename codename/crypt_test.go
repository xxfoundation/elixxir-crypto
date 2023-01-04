////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package codename

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"gitlab.com/elixxir/crypto/backup"
	"gitlab.com/xx_network/crypto/csprng"
)

// Smoke test of encryptIdentity and decryptIdentity.
func Test_encryptIdentity_decryptIdentity(t *testing.T) {
	plaintext := []byte("Hello, World!")
	password := []byte("test_password")
	ciphertext := encryptIdentity(plaintext, password, rand.Reader)
	decrypted, err := decryptIdentity(ciphertext, password)
	if err != nil {
		t.Errorf("%+v", err)
	}

	for i := range plaintext {
		if plaintext[i] != decrypted[i] {
			t.Errorf("%b != %b", plaintext[i], decrypted[i])
		}
	}
}

// Tests that decryptIdentity does not panic when given too little data.
func Test_decryptIdentity_ShortDataError(t *testing.T) {
	// Anything under 24 should cause an error.
	ciphertext := []byte{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	_, err := decryptIdentity(ciphertext, []byte("dummyPassword"))
	expectedErr := fmt.Sprintf(readNonceLenErr, 24)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Unexpected error on short decryption."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}

	// Empty string shouldn't panic should cause an error.
	ciphertext = []byte{}
	_, err = decryptIdentity(ciphertext, []byte("dummyPassword"))
	expectedErr = fmt.Sprintf(readNonceLenErr, 0)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Unexpected error on short decryption."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Tests that decryptIdentity returns an error when an invalid password is used.
func Test_decryptIdentity_InvalidPasswordError(t *testing.T) {
	plaintext := []byte("Hello, World!")
	password := []byte("test_password")
	ciphertext := encryptIdentity(plaintext, password, rand.Reader)

	expectedErr := strings.Split(decryptWithPasswordErr, "%")[0]

	_, err := decryptIdentity(ciphertext, []byte("invalid password"))
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Unexpected error for invalid password."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Tests that deriveKey returns a key of the correct length and that it is the
// same for the same set of password and salt. Also checks that keys with the
// same salt or passwords do not collide.
func Test_deriveKey(t *testing.T) {
	p := testParams()
	salts := make([][]byte, 6)
	passwords := make([]string, len(salts))
	keys := make(map[string]bool, len(salts)*len(passwords))

	for i := range salts {
		prng := csprng.NewSystemRNG()
		salt, _ := makeSalt(prng)
		salts[i] = salt

		password := make([]byte, 16)
		_, _ = prng.Read(password)
		passwords[i] = base64.StdEncoding.EncodeToString(password)[:16]
	}

	for _, salt := range salts {
		for _, password := range passwords {
			key := deriveKey(password, salt, p)

			// Check that the length of the key is correct
			if len(key) != keyLen {
				t.Errorf("Incorrect key length.\nexpected: %d\nreceived: %d",
					keyLen, len(key))
			}

			// Check that the same key is generated when the same password and
			// salt are used
			key2 := deriveKey(password, salt, p)

			if !bytes.Equal(key, key2) {
				t.Errorf("Keys with same password and salt do not match."+
					"\nexpected: %v\nreceived: %v", key, key2)
			}

			if keys[string(key)] {
				t.Errorf("Key already exists.")
			}
			keys[string(key)] = true
		}
	}
}

// Tests that multiple calls to makeSalt results in unique salts of the
// specified length.
func Test_makeSalt(t *testing.T) {
	salts := make(map[string]bool, 50)
	for i := 0; i < 50; i++ {
		salt, err := makeSalt(csprng.NewSystemRNG())
		if err != nil {
			t.Errorf("MakeSalt returned an error: %+v", err)
		}

		if len(salt) != saltLen {
			t.Errorf("Incorrect salt length.\nexpected: %d\nreceived: %d",
				saltLen, len(salt))
		}

		if salts[string(salt)] {
			t.Errorf("Salt already exists (%d).", i)
		}
		salts[string(salt)] = true
	}
}

// Tests that makeSalt returns an error when the RNG returns an error when read.
func Test_makeSalt_ReadError(t *testing.T) {
	b := bytes.NewBuffer([]byte{})

	expectedErr := strings.Split(readSaltErr, "%")[0]
	_, err := makeSalt(b)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Unexpected error when RNG returns a read error."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Tests that makeSalt returns an error when the RNG does not return enough
// bytes.
func Test_makeSalt_ReadNumBytesError(t *testing.T) {
	b := bytes.NewBuffer(make([]byte, saltLen/2))

	expectedErr := fmt.Sprintf(saltNumBytesErr, saltLen, saltLen/2)
	_, err := makeSalt(b)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Unexpected error when RNG does not return enough bytes."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// testParams returns params used in testing that are quick.
func testParams() backup.Params {
	return backup.Params{
		Time:    1,
		Memory:  1,
		Threads: 1,
	}
}
