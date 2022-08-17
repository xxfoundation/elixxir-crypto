////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package crust

import (
	"gitlab.com/xx_network/crypto/signature/rsa"
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

	for i := 0; i < numTests; i++ {
		sig, err := SignUpload(notRand, privKey, files[i], timestamps[i])
		if err != nil {
			t.Fatalf("Failed to generate sig %d/%d: %v", i, numTests, err)
		}

		err = VerifyUpload(privKey.GetPublic(), files[i], timestamps[i], sig)
		if err != nil {
			t.Fatalf("Failed to verify signature for test %d/%v: %v", i, numTests, err)
		}
	}

}
