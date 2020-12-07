/* Copyright 2020 xx network SEZC

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.

*/

package e2e

import (
	"encoding/base64"
	"gitlab.com/elixxir/primitives/format"
	"math/rand"
	"reflect"
	"testing"
)

// Tests that running Crypt twice encrypts and then decrypts the message
func TestCryptCrypt(t *testing.T) {
	// Create key and message
	key := Key{}
	key[0] = 2
	fp := format.Fingerprint{}
	fp[0] = 3
	msg := []byte{5, 12, 11}

	// Encrypt key
	encMsg := Crypt(key, fp, msg)

	// Decrypt key
	dncMsg := Crypt(key, fp, encMsg)

	if !reflect.DeepEqual(dncMsg, msg) {
		t.Errorf("Encrypt() did not encrypt the message correctly\n\treceived: %v\n\texpected: %v", dncMsg, msg)
	}
}

// Ensures that encrypted messages are consistency encrypted to the same value
// (when replacing the random number generater with a pseudo one)
func TestEncrypt_Consistency(t *testing.T) {
	const messageSize = 100
	// Set up expected values with base64 encoding
	expectedMsgs := []string{
		"UGVCeJkjdpZ4iVHs4DaJCZSHMS0bs5fpF9mb8ZBkat+o/mUXe1JCRBbgF0Z6whcy3m3z" +
			"eBYp4/Tgdt3hhSssxONndKrel/Xkfi08/lfTZNLqbzDw/42SCss1Sq5S/QT6D3os" +
			"iA==",
		"aDW1HLOxKC0eFOjFGwj4AGyvnumbrXzA9axxu9sVGzcbvWb7ar04+IHS4IA/K2QXgLW+" +
			"RofNVjZHICha4HT3aI3sbY2ZYScsqhdJBUH5ivx/uUlwh7Pt2d6qtPwhyO1ZwFFA" +
			"FA==",
		"HqKPDP9Hvai61hFc5UKCq84ryjWI4WdMih5WZP+Kj4jbVYuG5ckbEzN75sO6jYOZGIzg" +
			"2M3Kjo4lUDIu9QUx7UCbyiLcCiqGK9OuQ89PtxhNR6aCHm374LD78AUtrEkMlcTy" +
			"Og==",
		"PPYCnDivI7m8xwctIVeslg/KYnbl3BLWiOOpcniiAezg+KDQ7iWARvpk5TFy7PaLIlFn" +
			"4fSYK7cb1hZt1KdHKJvXoVICR5a3SbzVQ2RN1XPzbFvlf6A8nvVR2NXrBWBr8a7K" +
			"Lg==",
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

		msgBytes := make([]byte, messageSize)
		msgPrng.Read(msgBytes)
		msgs = append(msgs, msgBytes)
	}

	//encrypt messages with fingerprints and check they match the expected
	for i := 0; i < len(msgs); i++ {
		encMsg := Crypt(keys[i], fingerprints[i], msgs[i])

		// Decode base64 encoded expected message
		expectedMsg, _ := base64.StdEncoding.DecodeString(expectedMsgs[i])
		if !reflect.DeepEqual(encMsg, expectedMsg) {
			t.Errorf("EncryptUnsafe() did not produce the correct message on test %v\n\treceived: %#v\n\texpected: %#v", i, encMsg, expectedMsg)
			//fmt.Println(base64.StdEncoding.EncodeToString(encMsg))
		}
	}
}
