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

// Unit test: Tests that the signature from SignUpload
// will not fail if passed into VerifyUpload with the
// same data passed in.
func TestSignVerifyUpload(t *testing.T) {

	// use insecure seeded rng to ensure repeatability
	notRand := &CountingReader{count: uint8(0)}

	// Generate files
	files := make([][]byte, numTests)
	for i := 0; i < numTests; i++ {
		file := make([]byte, 2048)
		notRand.Read(file)

		files[i] = file
	}

	// Generate timestamps
	timestamps := make([][]byte, numTests)
	for i := 0; i < numTests; i++ {
		ts := make([]byte, 8)
		notRand.Read(ts)

		timestamps[i] = ts
	}

	// Generate a private key
	privKey, err := rsa.GenerateKey(notRand, 4096)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Sign and verify
	for i := 0; i < numTests; i++ {
		// Sign data
		sig, err := SignUpload(notRand, privKey, files[i], timestamps[i])
		if err != nil {
			t.Fatalf("Failed to generate sig %d/%d: %v", i, numTests, err)
		}

		// Use signature provided above and verify
		err = VerifyUpload(privKey.GetPublic(), files[i], timestamps[i], sig)
		if err != nil {
			t.Fatalf("Failed to verify signature for test %d/%v: %v", i, numTests, err)
		}
	}

}

// Unit test: Generate signatures using pre-canned data
// and compare it against the expected pre-canned data.
func TestSignUpload_Consistency(t *testing.T) {
	// use insecure seeded rng to ensure repeatability
	notRand := &CountingReader{count: uint8(0)}

	// Generate files
	files := make([][]byte, numTests)
	for i := 0; i < numTests; i++ {
		file := make([]byte, 2048)
		notRand.Read(file)

		files[i] = file
	}

	// Generate timestamps
	timestamps := make([][]byte, numTests)
	for i := 0; i < numTests; i++ {
		ts := make([]byte, 8)
		notRand.Read(ts)

		timestamps[i] = ts
	}

	// Generate a private key
	privKey, err := rsa.GenerateKey(notRand, 4096)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Generate signatures
	signatures := make([]string, numTests)
	for i := 0; i < numTests; i++ {
		// Sign data
		notRand = &CountingReader{count: uint8(0)}
		sig, err := SignUpload(notRand, privKey, files[i], timestamps[i])
		if err != nil {
			t.Fatalf("Failed to SignUpload for %d/%d: %v", i, numTests, err)
		}

		signatures[i] = base64.StdEncoding.EncodeToString(sig)
	}

	// Expected (pre-canned) output
	expectedSignatures := []string{
		"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",
	}

	// Check generated output is consisted with pre-canned output
	if !reflect.DeepEqual(expectedSignatures, signatures) {
		t.Fatalf("Generated data does not match pre-canned data."+
			"\nExpected: %v"+
			"\nReceived: %v", expectedSignatures, signatures)
	}

}
