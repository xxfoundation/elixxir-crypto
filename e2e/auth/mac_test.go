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

// Tests that the generated proofs do not change for MakeMac.
func TestMakeMac_Consistency(t *testing.T) {

	expected := []string{
		"XNc4xg5johaQAwOAU25kTGPnFJWwdizyp1R8QO0bXos=",
		"FOxMuD6rLUL4KZdtq87uTrJk7ul2roTMqAFNvp6F6NY=",
		"IaJMMU+N06DHXWdrmjmh09mUwZtJKZgjmh1BG7awX9g=",
		"J9Epes8QZ33f2ZXYnhCo74Wisej3MdntuNLeeC8JDSM=",
		"dBGm2a7tVKOk0t9c9dnS2cERGi89j0dWXJMDlFmK9hQ=",
	}

	grp := getGrp()
	prng := rand.New(rand.NewSource(42))

	for i := 0; i < len(expected); i++ {
		privKey := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength, grp, prng)
		pubkey := diffieHellman.GeneratePublicKey(privKey, grp)
		baseKey := diffieHellman.GenerateSessionKey(privKey, pubkey, grp)
		encryptedPayload := make([]byte, 128)
		prng.Read(encryptedPayload)
		mac := MakeMac(baseKey.Bytes(), encryptedPayload)
		mac64 := base64.StdEncoding.EncodeToString(mac)

		if expected[i] != mac64 {
			t.Errorf("received and expected do not match at index %v\n"+
				"\treceived: %s\n\texpected: %s", i, mac64, expected[i])
		}
	}
}

// Tests that the generated MACs are verified.
func TestVerifyMac(t *testing.T) {
	const numTests = 100

	grp := getGrp()
	prng := rand.New(rand.NewSource(69))

	for i := 0; i < numTests; i++ {
		privKey := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength, grp, prng)
		pubkey := diffieHellman.GeneratePublicKey(privKey, grp)
		baseKey := diffieHellman.GenerateSessionKey(privKey, pubkey, grp)
		encryptedPayload := make([]byte, 128)
		prng.Read(encryptedPayload)
		mac := MakeMac(baseKey.Bytes(), encryptedPayload)

		if !VerifyMac(baseKey.Bytes(), encryptedPayload, mac) {
			t.Errorf("MAC could not be verified at index %v", i)
		}
	}
}

// Tests that the bad MACs are not verified.
func TestVerifyMac_Bad(t *testing.T) {
	const numTests = 100

	grp := getGrp()
	prng := rand.New(rand.NewSource(69))

	for i := 0; i < numTests; i++ {
		privKey := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength, grp, prng)
		pubkey := diffieHellman.GeneratePublicKey(privKey, grp)
		baseKey := diffieHellman.GenerateSessionKey(privKey, pubkey, grp)
		encryptedPayload := make([]byte, 128)
		prng.Read(encryptedPayload)
		mac := make([]byte, 32)
		prng.Read(mac)

		if VerifyMac(baseKey.Bytes(), encryptedPayload, mac) {
			t.Errorf("MAC was verified at index %v when it is bad", i)
		}
	}
}

// Tests that modifying the inputs leads to different MACs.
func TestMacInputProof(t *testing.T) {
	grp := getGrp()
	prng := rand.New(rand.NewSource(69))

	// Create a list to store the created MACs; it will be iterated though to
	// show none are the same
	var macList [][]byte

	// Create 9 MACs, all with different arrangements of inputs
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			for k := 0; k < 4; k++ {
				for l := 0; l < 4; l++ {
					privKey1 := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength+i, grp, prng)
					privKey2 := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength+j, grp, prng)
					pubkey := diffieHellman.GeneratePublicKey(privKey1, grp)
					baseKey := diffieHellman.GenerateSessionKey(privKey2, pubkey, grp)
					encryptedPayload := make([]byte, 128+l)
					prng.Read(encryptedPayload)
					mac := MakeMac(baseKey.Bytes(),
						encryptedPayload)

					macList = append(macList, mac)
				}

			}
		}
	}

	// Show that no MACs are the same
	for i := 0; i < len(macList); i++ {
		for j := i + 1; j < len(macList); j++ {
			if bytes.Equal(macList[i], macList[j]) {
				t.Errorf("MAC %d and %d are the same\n"+
					"\t first: %v \n\t second: %v", i, j, macList[i], macList[j])
			}
		}
	}
}
