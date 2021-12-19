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

// TestMakeAuthKey_Smoke tests basic functionality of MakeAuth s.t. it
// produces the same auth key on both sides of a connection
func TestMakeAuthKey_Smoke(t *testing.T) {
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
	key1, vector1 := MakeAuthKey(privKey1, pubKey2, grp)
	key2, vector2 := MakeAuthKey(privKey2, pubKey1, grp)

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
		"lGzqWPllJvh6m+3P3l1pIaMsOWCkL/2BDlfPO/shgUY=",
		"kWq8gs9lS7Fshmu7U52k1AAtdUtgsu/RelYAZK4U5Ho=",
		"vauhaqhUB8KLUzKlhOgaL/qPVNGJP1e6BOGbtuCcbK0=",
		"ta8FsTUN7JhYd+lTSwEA20t1TWo3SnrMaJvQifxdpYA=",
		"9K14uzjAxgR1uQzQ8OYgLkUM7tCx8lB0oemYEZ5l62w=",
	}

	// Hardcoded expected values for vectors
	expectedVectors := []string{
		"ixUnc8qSvWrMzq5ziYq945wB2ZTL0ASqJ/5g68WU9+c=",
		"wSDtNuv/ilJS4KX5cNrLx912TIKr0pBtEjg3u/UgIuk=",
		"xKuplHpcK/02UtuAp5RnZufy57+yySmlma0TtAksW9M=",
		"0/TajGR6qVtfe7KroMnbB5/mkD7K2MKhpgDMzeM9YpE=",
		"Um9x38pJ2Q/TRUvzO9+1d0E1WQN8OAiPVssMTMbKdgc=",
	}

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
		key, vector := MakeAuthKey(myPrivKey, partnerPubKey, grp)

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
	// Generate a group
	grp := getGrp()

	// Generate a pseudo-rng
	prng := rand.New(rand.NewSource(42))

	// Generate the two keys, public and private
	myPrivKey := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength, grp, prng)
	partnerPubKey := diffieHellman.GeneratePublicKey(diffieHellman.GeneratePrivateKey(512, grp, prng), grp)

	// Create the auth key
	key, vector := MakeAuthKey(myPrivKey, partnerPubKey, grp)

	// Generate 'bad' (ie different) input values
	badPrng := rand.New(rand.NewSource(69))
	badPrivKey := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength, grp, badPrng)
	badPartnerPubKey := diffieHellman.GeneratePublicKey(diffieHellman.GeneratePrivateKey(512, grp, badPrng), grp)
	// Vary the private key inputted, check the outputs
	badKey, badVector := MakeAuthKey(badPrivKey, partnerPubKey, grp)
	if bytes.Equal(key, badKey) || bytes.Equal(vector, badVector) {
		t.Errorf("Outputs generated were identical when our private key varied")
	}

	// Vary the public key inputted, check the outputs
	badKey, badVector = MakeAuthKey(myPrivKey, badPartnerPubKey, grp)
	if bytes.Equal(key, badKey) || bytes.Equal(vector, badVector) {
		t.Errorf("Outputs generated were identical when the parner public key varied")
	}
}
