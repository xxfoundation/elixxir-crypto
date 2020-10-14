////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////
package auth

import (
	"bytes"
	"encoding/base64"
	"gitlab.com/elixxir/crypto/diffieHellman"
	"math/rand"
	"testing"
)

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

	expectedFingerPrints := []string{
		"I5vse9t+QzlDmClZSNkLPVvTmWJ++YT/fTbyiy1I/rI=",
		"xWrc3RJE6W+2FGv90m3+txH0m6xIojOq04xATvpa//U=",
		"zdGCji6CPmmGQ5euPSjkWUJBnkPt2VDgU49XLneyo28=",
		"1M98jFztIo3iUVF2ndJyL0POlD1Zzp9d7nhvI70ZRTY=",
		"Odhht6oFXBxQ4wJTfgYKTd4QGhOw9bX4hhTjwgN7heM=",
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
		key, vector, fpVec := MakeAuthKey(myPrivKey, partnerPubKey, salt, grp)

		// Encode the auth key for comparison
		key64Encoded := base64.StdEncoding.EncodeToString(key)

		// Encode the vector for comparison
		vector64Encoded := base64.StdEncoding.EncodeToString(vector)

		fpVec64 := base64.StdEncoding.EncodeToString(fpVec[:])

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

		if expectedFingerPrints[i] != fpVec64 {
			t.Errorf("received and expected do not match at index %v for fingerprint\n"+
				"\treceived: %s\n\texpected: %s", i, fpVec64, expectedFingerPrints[i])

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
	key, vector, fpVec := MakeAuthKey(myPrivKey, partnerPubKey, salt, grp)

	// Generate 'bad' (ie different) input values
	badPrng := rand.New(rand.NewSource(69))
	badPrivKey := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength, grp, badPrng)
	badPartnerPubKey := diffieHellman.GeneratePublicKey(diffieHellman.GeneratePrivateKey(512, grp, badPrng), grp)
	badSalt := []byte("BadSalt")

	// Vary the private key inputted, check the outputs
	badKey, badVector, badFPVec := MakeAuthKey(badPrivKey, partnerPubKey, salt, grp)
	if bytes.Equal(key, badKey) || bytes.Equal(vector, badVector) || bytes.Equal(fpVec[:], badFPVec[:]) {
		t.Errorf("Outputs generated were identical when our private key varied")
	}

	// Vary the public key inputted, check the outputs
	badKey, badVector, badFPVec = MakeAuthKey(myPrivKey, badPartnerPubKey, salt, grp)
	if bytes.Equal(key, badKey) || bytes.Equal(vector, badVector) || bytes.Equal(fpVec[:], badFPVec[:]) {
		t.Errorf("Outputs generated were identical when the parner public key varied")
	}

	// Vary the salt inputted, check the outputs
	badKey, badVector, badFPVec = MakeAuthKey(badPrivKey, badPartnerPubKey, badSalt, grp)
	if bytes.Equal(key, badKey) || bytes.Equal(vector, badVector) || bytes.Equal(fpVec[:], badFPVec[:]) {
		t.Errorf("Outputs generated were identical when the salt varied")
	}

}
