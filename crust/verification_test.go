////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package crust

import (
	"encoding/base64"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"testing"
)

// Unit test: Tests that the signature from SignVerification
// will not fail if passed into VerifyVerificationSignature with the
// same data passed in.
func TestSignVerifyVerification(t *testing.T) {

	// use insecure seeded rng to ensure repeatability
	notRand := &CountingReader{count: uint8(0)}

	// Generate usernames
	usernames := make([]string, numTests)
	for i := 0; i < numTests; i++ {
		username := make([]byte, 25)
		notRand.Read(username)

		usernames[i] = base64.StdEncoding.EncodeToString(username)
	}

	// Generate reception keys
	receptionKeys := make([][]byte, numTests)
	for i := 0; i < numTests; i++ {
		receptionKey := make([]byte, 32)
		notRand.Read(receptionKey)
		receptionKeys[i] = receptionKey
	}

	// Generate a private key
	privKey, err := rsa.GenerateKey(notRand, 4096)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Sign and verify
	for i := 0; i < numTests; i++ {
		sig, err := SignVerification(notRand, privKey,
			usernames[i], receptionKeys[i])
		if err != nil {
			t.Fatalf("Failed to generate sig %d/%d: %v", i, numTests, err)
		}

		err = VerifyVerificationSignature(privKey.GetPublic(), usernames[i], receptionKeys[i], sig)
		if err != nil {
			t.Fatalf("Failed to verify signature for test %d/%v: %v", i, numTests, err)
		}
	}

}
