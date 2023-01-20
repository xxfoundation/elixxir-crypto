////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

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
		"+gueVocoCTzjwQ4x2kYHR+otKpon0T7NIvUgrC4WTB34sVJv2msD+fsp509zVZxCk9R4" +
			"l8HWxSbxQXy7xvzNjp4c1U1G/p0J9xzIVTPxdaYo5NIDS7kd4brTSDFWv3GhmAae" +
			"1A==",
		"SDy5LnQuKrmnM53BxHFkL+NOvj8bGWm5j2iJVoRoZVkrJqahrjlG4E3zbCiI/uXqqna6" +
			"Q1nBZWhv1YmW1Leh3t0lBIfirj/0xJOwm2Bm8Cb3tvMXrZ6+m5b+l7oqrR2hjCyZ" +
			"Xg==",
		"L7vuk4rtDZYu+YzcCEch62j07LM8cAxN9/Tq9rRuVKhptrxO+97iwcWnqC/kjKciP5hR" +
			"kj7IFTo5bUJBi1yGWA5x1mp1TyQuHwcvHUsDEjXppokZrEW1wnsGXx9omIBvqca+" +
			"8w==",
		"D5WfKGLBkgA8Sg8VWhVUeFm2RjIArxOS5luwcCxkQkTO2ULh/9MqL7MvJ/rEPcryX9vO" +
			"NaCgY9wn1V6aYpZkSFzFvIsDKJDnfE/rz6hrDBm6X2x6EmDDb2MCAXYrmvHdQaa/" +
			"/A==",
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
