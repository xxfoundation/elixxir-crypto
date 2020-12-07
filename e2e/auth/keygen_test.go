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

package auth

import (
	"bytes"
	"encoding/base64"
	"gitlab.com/elixxir/crypto/diffieHellman"
	"math/rand"
	"testing"
)

// TestMakeAuthKey_Smoke tests basic functionality of MakeAuth s.t. it
// produces the same auth key on both sides of a connection
func TestMakeAuthKey_Smoke(t *testing.T) {
	// Initialize a mock salt
	salt := []byte("salt")

	// Generate a group
	grp := getGrp()

	// Generate a pseudo-rng
	prng := rand.New(rand.NewSource(42))

	// Generate the two keys, public and private
	keyLen := diffieHellman.DefaultPrivateKeyLength
	privKey1 := diffieHellman.GeneratePrivateKey(keyLen, grp, prng)
	pubKey1 := diffieHellman.GeneratePublicKey(privKey1, grp)
	privKey2 := diffieHellman.GeneratePrivateKey(keyLen, grp, prng)
	pubKey2 := diffieHellman.GeneratePublicKey(privKey2, grp)

	// Create the auth keys
	key1, vector1 := MakeAuthKey(privKey1, pubKey2, salt, grp)
	key2, vector2 := MakeAuthKey(privKey2, pubKey1, salt, grp)

	for i := 0; i < len(key1); i++ {
		if key1[i] == key2[i] {
			continue
		}
		t.Errorf("MakeAuthKey Key Mismatch at %d: %d != %d",
			i, key1[i], key2[i])
	}

	for i := 0; i < len(vector1); i++ {
		if vector1[i] == vector2[i] {
			continue
		}
		t.Errorf("MakeAuthKey Vector Mismatch at %d: %d != %d",
			i, vector1[i], vector2[i])
	}

}

// Check the consistency of outputs for MakeAuthKey
func TestMakeAuthKey_Consistency(t *testing.T) {
	// Hardcoded expected values for auth keys
	expectedKeys := []string{
		"0PSG0GR6/QCcQ+P5+HfGbYyZYrX04SnVuk37tHnFvu0=",
		"8CSvWeTn5CujIO07prc1MA1WXueC7FXBP/35JoePyuY=",
		"7Wv51EGdOagD8KJNPIZ8Khp3+WHRfyQ3VZHABvnXlRM=",
		"QLe72xIwNkiDWZfVW0tuxEode+ZotkZNj9vSPzM0rKQ=",
		"GUSK/PWHEmur0eNzMzmAzjLDEXRm3e8qna1XfopmUyo=",
	}

	// Hardcoded expected values for vectors
	expectedVectors := []string{
		"tPA6P5FVlXT/k+g52POlo8D9GFtSbaGRDHHKYBtfzu0=",
		"ns/XQvCsecnOnbv/rUKWM9lpzhHzvuqmxNEcn7b3rkM=",
		"8OzaFjLJlGTqKV4k562I3cl0U9jzQ6BoDxS64X2V9iI=",
		"dI7l2aXYbMATqsf7RRb1H+06AUO8dOB+kNAmzWMJoGg=",
		"PFrcY1rjHHehkPK++chBSbT9+SPUIfLMn1ZkRzX0Z18=",
	}

	// Initialize a mock salt
	salt := []byte("salt")

	// Generate a group
	grp := getGrp()

	// Generate a pseudo-rng
	prng := rand.New(rand.NewSource(42))

	// Generate a key for every expected value above
	// Check if they match the expected value
	for i := 0; i < len(expectedKeys); i++ {
		// Generate the two keys, public and private
		myPrivKey := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength, grp, prng)
		partnerPubKey := diffieHellman.GeneratePublicKey(diffieHellman.GeneratePrivateKey(512, grp, prng), grp)

		// Create the auth key
		key, vector := MakeAuthKey(myPrivKey, partnerPubKey, salt, grp)

		// Encode the auth key for comparison
		key64Encoded := base64.StdEncoding.EncodeToString(key)

		// Encode the vector for comparison
		vector64Encoded := base64.StdEncoding.EncodeToString(vector)

		// Check if the key matches the expected value
		if expectedKeys[i] != key64Encoded {
			t.Errorf("received and expected do not match at index %v for keys\n"+
				"\treceived: %s\n\texpected: %s", i, key64Encoded, expectedKeys[i])
		}

		// Check if the vector matches the expected value
		if expectedVectors[i] != vector64Encoded {
			t.Errorf("received and expected do not match at index %v for vectors\n"+
				"\treceived: %s\n\texpected: %s", i, vector64Encoded, expectedVectors[i])
		}
	}

}

// Check that for every input varied in MakeAuthKey, outputs vary
func TestMakeAuthKey_InputVariance(t *testing.T) {
	// Initialize a mock salt
	salt := []byte("salt")

	// Generate a group
	grp := getGrp()

	// Generate a pseudo-rng
	prng := rand.New(rand.NewSource(42))

	// Generate the two keys, public and private
	myPrivKey := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength, grp, prng)
	partnerPubKey := diffieHellman.GeneratePublicKey(diffieHellman.GeneratePrivateKey(512, grp, prng), grp)

	// Create the auth key
	key, vector := MakeAuthKey(myPrivKey, partnerPubKey, salt, grp)

	// Generate 'bad' (ie different) input values
	badPrng := rand.New(rand.NewSource(69))
	badPrivKey := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength, grp, badPrng)
	badPartnerPubKey := diffieHellman.GeneratePublicKey(diffieHellman.GeneratePrivateKey(512, grp, badPrng), grp)
	badSalt := []byte("BadSalt")

	// Vary the private key inputted, check the outputs
	badKey, badVector := MakeAuthKey(badPrivKey, partnerPubKey, salt, grp)
	if bytes.Equal(key, badKey) || bytes.Equal(vector, badVector) {
		t.Errorf("Outputs generated were identical when our private key varied")
	}

	// Vary the public key inputted, check the outputs
	badKey, badVector = MakeAuthKey(myPrivKey, badPartnerPubKey, salt, grp)
	if bytes.Equal(key, badKey) || bytes.Equal(vector, badVector) {
		t.Errorf("Outputs generated were identical when the parner public key varied")
	}

	// Vary the salt inputted, check the outputs
	badKey, badVector = MakeAuthKey(badPrivKey, badPartnerPubKey, badSalt, grp)
	if bytes.Equal(key, badKey) || bytes.Equal(vector, badVector) {
		t.Errorf("Outputs generated were identical when the salt varied")
	}

}
