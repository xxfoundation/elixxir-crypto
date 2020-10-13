////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////
package auth

import (
	"encoding/base64"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/diffieHellman"
	"gitlab.com/elixxir/crypto/large"
	"math/rand"
	"testing"
)

func TestMakeAuthKey_Consistency(t *testing.T) {
	// Hardcoded expected values
	expected := []string{
		"0PSG0GR6/QCcQ+P5+HfGbYyZYrX04SnVuk37tHnFvu0=",
		"8CSvWeTn5CujIO07prc1MA1WXueC7FXBP/35JoePyuY=",
		"7Wv51EGdOagD8KJNPIZ8Khp3+WHRfyQ3VZHABvnXlRM=",
		"QLe72xIwNkiDWZfVW0tuxEode+ZotkZNj9vSPzM0rKQ=",
		"GUSK/PWHEmur0eNzMzmAzjLDEXRm3e8qna1XfopmUyo=",
	}

	// Initialize a mock salt
	salt := []byte("salt")

	// Generate a group
	grp := getGrp()

	// Generate a pseudo-rng
	prng := rand.New(rand.NewSource(42))

	// Generate a key for every expected value above
	// Check if they match the expected value
	for i := 0; i < len(expected); i++ {
		// Generate the two keys, public and private
		myPrivKey := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength, grp, prng)
		partnerPubKey := diffieHellman.GeneratePublicKey(diffieHellman.GeneratePrivateKey(512, grp, prng), grp)

		// Create the auth key
		key, _ := MakeAuthKey(myPrivKey, partnerPubKey, salt, grp)

		// Encode the auth key for comparison
		key64Encoded := base64.StdEncoding.EncodeToString(key)

		// Check if the key matches the expected value
		if expected[i] != key64Encoded {
			t.Errorf("received and expected do not match at index %v\n"+
				"\treceived: %s\n\texpected: %s", i, key64Encoded, expected[i])
		}
	}

}

//Tests that the generated auth keys are verified
func TestMakeAuthKey_Verified(t *testing.T) {
	// Set up a number of tests to perform
	const numTests = 100

	// Initialize a mock salt
	salt := []byte("salt")

	// Generate a group
	grp := getGrp()

	// Generate a pseudo-rng
	prng := rand.New(rand.NewSource(42))

	// Generate and verify a key NUMTESTS times
	for i := 0; i < numTests; i++ {
		// Generate the two keys, public and private
		myPrivKey := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength, grp, prng)
		partnerPubKey := diffieHellman.GeneratePublicKey(diffieHellman.GeneratePrivateKey(512, grp, prng), grp)

		// Create the auth key
		key, _ := MakeAuthKey(myPrivKey, partnerPubKey, salt, grp)

		// If the auth key cannot be verified, this run fails
		if !VerifyAuthKey(myPrivKey, partnerPubKey, salt, grp, key) {
			t.Errorf("Auth key could not be verified at index %v", i)
		}
	}
}

//Tests that bad proofs are not verified
func TestVerifyOwnershipProof_Bad(t *testing.T) {
	// Set up a number of tests to perform
	const numTests = 100

	// Initialize a mock salt
	salt := []byte("salt")

	// Generate a group
	grp := getGrp()

	// Generate a pseudo-rng
	prng := rand.New(rand.NewSource(42))

	// Generate a bad auth key and check it's not verified
	for i := 0; i < numTests; i++ {
		// Generate the two keys, public and private
		myPrivKey := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength, grp, prng)
		partnerPubKey := diffieHellman.GeneratePublicKey(diffieHellman.GeneratePrivateKey(512, grp, prng), grp)

		// Generate a random, non-proper auth key
		badKey := make([]byte, 32)
		prng.Read(badKey)

		// If this non proper auth key is verified, this run fails
		if VerifyAuthKey(myPrivKey, partnerPubKey, salt, grp, badKey) {
			t.Errorf("AuthKey was verified at index %v when it is bad", i)
		}

	}
}

// Helper function which generate a group for testing
func getGrp() *cyclic.Group {
	primeString := "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF"
	p := large.NewIntFromString(primeString, 16)
	g := large.NewInt(2)
	return cyclic.NewGroup(p, g)
}
