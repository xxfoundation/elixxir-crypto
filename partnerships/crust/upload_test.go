////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package crust

import (
	"encoding/base64"
	"encoding/binary"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"reflect"
	"testing"
	"time"
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
	timestamps := make([]time.Time, numTests)
	now := time.Now()
	for i := 0; i < numTests; i++ {
		duration := make([]byte, 8)
		notRand.Read(duration)

		randDuration := binary.BigEndian.Uint64(duration)
		timestamps[i] = now.Add(time.Duration(randDuration))
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
		err = VerifyUpload(privKey.GetPublic(), timestamps[i], files[i], sig)
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

	// Generate timestamps. use hardcoded time instead of time.Now for consistency.
	timestamps := make([]time.Time, numTests)
	testTime, err := time.Parse(time.RFC3339,
		"2012-12-21T22:08:41+00:00")
	if err != nil {
		t.Fatalf("SignVerify error: "+
			"Could not parse precanned time: %v", err.Error())
	}
	for i := 0; i < numTests; i++ {
		duration := make([]byte, 8)
		notRand.Read(duration)

		randDuration := binary.BigEndian.Uint64(duration)
		timestamps[i] = testTime.Add(time.Duration(randDuration))
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
