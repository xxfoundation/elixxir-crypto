////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package e2e

import (
	"encoding/base64"
	"github.com/pkg/errors"
	"gitlab.com/elixxir/primitives/format"
	"math/rand"
	"reflect"
	"testing"
)

// Tests the functionality of Encrypt() and Decrypt() by encrypting a message
// and check that it is the same when decrypting
func TestEncryptDecrypt(t *testing.T) {
	// Create key and message
	key := Key{}
	key[0] = 2
	fp := format.Fingerprint{}
	fp[0] = 3
	msg := []byte{5, 12, 11}

	// Encrypt key
	encMsg, err := Encrypt(key, fp, msg, 200)

	if err != nil {
		t.Errorf("Encrypt() produced an unexpected error\n\treceived: %v\n\texpected: %v", err, nil)
	}

	// Decrypt key
	dncMsg, err := Decrypt(key, fp, encMsg)

	if !reflect.DeepEqual(dncMsg, msg) {
		t.Errorf("Encrypt() did not encrypt the message correctly\n\treceived: %v\n\texpected: %v", dncMsg, msg)
	}
}

// Checks that leading zeroes in a message are not stripped
func TestEncryptDecrypt_LeadingZeroes(t *testing.T) {

	// Create key and message
	key := Key{}
	key[0] = 2
	fp := format.Fingerprint{}
	fp[0] = 3

	msg := []byte{0, 0, 11, 5, 255, 0}

	// Encrypt key
	encMsg, err := Encrypt(key, fp, msg, 200)

	if err != nil {
		t.Errorf("Encrypt() produced an unexpected error\n\treceived: %v\n\texpected: %v", err, nil)
	}

	// Decrypt key
	dncMsg, err := Decrypt(key, fp, encMsg)

	if !reflect.DeepEqual(dncMsg, msg) {
		t.Errorf("Encrypt() did not encrypt the message correctly\n\treceived: %v\n\texpected: %v", dncMsg, msg)
	}
}

// Ensures that encrypted messages are consistency encrypted to the same value
// (when replacing the random number generater with a pseudo one)
func TestEncrypt_Consistency(t *testing.T) {
	// Set up expected values with base64 encoding
	expectedMsgs := []string{
		"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",
	}
	// Generate keys, fingerprints and messages
	var keys []Key
	var fingerprints []format.Fingerprint
	var msgs [][]byte
	keyPrng := rand.New(rand.NewSource(42))
	fingperprintPrng := rand.New(rand.NewSource(420))
	msgPrng := rand.New(rand.NewSource(69))
	for i := 0; i < len(expectedMsgs); i++ {
		key := Key{}
		keyPrng.Read(key[:])
		keys = append(keys, key)

		fp := format.Fingerprint{}
		fingperprintPrng.Read(fp[:])
		fingerprints = append(fingerprints, fp)

		msgBytes := make([]byte, format.ContentsLen)
		msgPrng.Read(msgBytes[:format.ContentsLen-2])
		msgs = append(msgs, msgBytes)
	}

	//encrypt messages with fingerprints and check they match the expected
	for i := 0; i < len(msgs); i++ {
		encMsg := CryptUnsafe(keys[i], fingerprints[i], msgs[i])

		// Decode base64 encoded expected message
		expectedMsg, _ := base64.StdEncoding.DecodeString(expectedMsgs[i])

		if !reflect.DeepEqual(encMsg, expectedMsg) {
			t.Errorf("EncryptUnsafe() did not produce the correct message on test %v\n\treceived: %#v\n\texpected: %#v", i, encMsg, expectedMsg)
			//fmt.Println(base64.StdEncoding.EncodeToString(encMsg))
		}
	}
}

// Checks that Decrypt() correctly responds to errors
func TestDecrypt_ErrorOnPaddingPrefix(t *testing.T) {
	// Create key and message
	rand.Seed(42)
	msg := make([]byte, 4000)
	rand.Read(msg)

	key := Key{}
	key[0] = 2
	fp := format.Fingerprint{}
	fp[0] = 3

	// Decrypt key
	dncMsg, err := Decrypt(key, fp, msg)

	if err == nil {
		t.Errorf("Decrypt() did not produce the expected error\n\treceived: %#v\n\texpected: %#v", err, errors.New("padding prefix invalid"))
	}

	if dncMsg != nil {
		t.Errorf("Decrypt() unexpectedly produced a non-nil message on error\n\treceived: %v\n\texpected: %v", dncMsg, nil)
	}
}
