////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package crust

import (
	"encoding/base64"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"reflect"
	"testing"
)

// Expected (pre-canned) input and output
var (
	Usernames = []string{
		"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGQ==",
		"GhscHR4fICEiIyQlJicoKSorLC0uLzAxMg==",
		"MzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKSw==",
	}

	ReceptionKeys = []string{
		"TE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpams=",
		"bG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJios=",
		"jI2Oj5CRkpOUlZaXmJmam5ydnp+goaKjpKWmp6ipqqs=",
	}

	ExpectedVerificationSignatures = []string{
		"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",
	}
)

// Unit test: Tests that the signature from SignVerification
// will not fail if passed into VerifyVerificationSignature with the
// same data passed in.
func TestSignVerifyVerification(t *testing.T) {

	// use insecure seeded rng to ensure repeatability
	notRand := &CountingReader{count: uint8(0)}

	// Load private key
	privKey, err := rsa.LoadPrivateKeyFromPem([]byte(PrivKeyPemEncoded))
	if err != nil {
		t.Fatalf("Failed to load private key: %v", err)
	}

	// Process reception keys
	receptionKeys := make([][]byte, numTests)
	for i := 0; i < numTests; i++ {
		receptionKeys[i], err = base64.StdEncoding.DecodeString(ReceptionKeys[i])
		if err != nil {
			t.Fatalf("Failed to decode reception key %d/%d: %v",
				i, numTests, err)
		}
	}

	// Sign and verify
	for i := 0; i < numTests; i++ {
		// Sign data
		sig, err := SignVerification(notRand, privKey,
			Usernames[i], receptionKeys[i])
		if err != nil {
			t.Fatalf("Failed to generate sig %d/%d: %v", i, numTests, err)
		}

		// Use signature provided above and verify
		err = VerifyVerificationSignature(privKey.GetPublic(), Usernames[i], receptionKeys[i], sig)
		if err != nil {
			t.Fatalf("Failed to verify signature for test %d/%v: %v", i, numTests, err)
		}
	}

}

// Unit test: Generate signatures using pre-canned data
// and compare it against the expected pre-canned data.
func TestSignVerification_Consistency(t *testing.T) {

	// Load private key
	privKey, err := rsa.LoadPrivateKeyFromPem([]byte(PrivKeyPemEncoded))
	if err != nil {
		t.Fatalf("Failed to load private key: %v", err)
	}

	// Process reception keys
	receptionKeys := make([][]byte, numTests)
	for i := 0; i < numTests; i++ {
		receptionKeys[i], err = base64.StdEncoding.DecodeString(ReceptionKeys[i])
		if err != nil {
			t.Fatalf("Failed to decode reception key %d/%d: %v",
				i, numTests, err)
		}
	}

	// Generate signatures
	signatures := make([]string, numTests)
	for i := 0; i < numTests; i++ {
		// Sign data
		notRand := &CountingReader{count: uint8(0)}
		sig, err := SignVerification(notRand, privKey,
			Usernames[i], receptionKeys[i])
		if err != nil {
			t.Fatalf("Failed to generate sig %d/%d: %v", i, numTests, err)
		}
		signatures[i] = base64.StdEncoding.EncodeToString(sig)

	}

	// Check generated output is consisted with precanned output
	if !reflect.DeepEqual(ExpectedVerificationSignatures, signatures) {
		t.Fatalf("Generated data does not match pre-canned data."+
			"\nExpected: %v"+
			"\nReceived: %v", ExpectedVerificationSignatures, signatures)
	}

}
