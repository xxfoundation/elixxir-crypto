////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package crust

import (
	"encoding/base64"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"testing"
	"time"
)

func TestJointVerify(t *testing.T) {

	UDPrivKey, err := rsa.LoadPrivateKeyFromPem([]byte(PrivKeyPemEncoded))
	if err != nil {
		t.Fatalf("Failed to load private key: %v", err)
	}

	// Process reception keys
	receptionKeys := make([]*rsa.PrivateKey, numTests)
	for i := 0; i < numTests; i++ {
		receptionKeys[i], err = rsa.LoadPrivateKeyFromPem([]byte(ReceptionKeys[i]))
		if err != nil {
			t.Fatalf("Failed to decode reception key %d/%d: %v",
				i, numTests, err)
		}

	}

	// Process files
	files := make([][]byte, numTests)
	for i := 0; i < numTests; i++ {
		files[i], err = base64.StdEncoding.DecodeString(Files[i])
		if err != nil {
			t.Fatalf("Failed to parse file: %v", err)
		}
	}

	// Process timestamps
	now := time.Unix(0, Now)
	timestamps := make([]time.Time, numTests)
	for i := 0; i < numTests; i++ {
		timestamps[i] = time.Unix(0, UnixNanoTimestamps[i])
	}

	// use insecure seeded rng to ensure repeatability
	notRand := &CountingReader{count: uint8(0)}

	// Generate signatures and verify them
	for i := 0; i < numTests; i++ {
		// Sign verification signature
		verifSig, err := SignVerification(notRand, UDPrivKey,
			Usernames[i], receptionKeys[i].GetPublic())
		if err != nil {
			t.Fatalf("Failed to generate verification sig %d/%d: "+
				"%v", i, numTests, err)
		}

		// Sign upload signatures
		uploadSig, err := SignUpload(notRand, receptionKeys[i], files[i], timestamps[i])
		if err != nil {
			t.Fatalf("Failed to generate upload sig "+
				"%d/%d: %v", i, numTests, err)
		}

		//try to verify the signature
		fileHash, err := HashFile(files[i])
		if err != nil {
			t.Fatalf("Failed to has file %d/%d: %v", i, numTests, err)
		}

		if err = JointVerify(UDPrivKey.GetPublic(), receptionKeys[i].GetPublic(),
			HashUsername(Usernames[i]), fileHash, verifSig, uploadSig,
			timestamps[i], now); err != nil {
			t.Fatalf("Joint Verification failed %d/%d: %v", i, numTests, err)
		}
	}
}

func TestJointVerify_BadVerificationSig(t *testing.T) {

	UDPrivKey, err := rsa.LoadPrivateKeyFromPem([]byte(PrivKeyPemEncoded))
	if err != nil {
		t.Fatalf("Failed to load private key: %v", err)
	}

	// Process reception keys
	receptionKeys := make([]*rsa.PrivateKey, numTests)
	for i := 0; i < numTests; i++ {
		receptionKeys[i], err = rsa.LoadPrivateKeyFromPem([]byte(ReceptionKeys[i]))
		if err != nil {
			t.Fatalf("Failed to decode reception key %d/%d: %v",
				i, numTests, err)
		}

	}

	// Process files
	files := make([][]byte, numTests)
	for i := 0; i < numTests; i++ {
		files[i], err = base64.StdEncoding.DecodeString(Files[i])
		if err != nil {
			t.Fatalf("Failed to parse file: %v", err)
		}
	}

	// Process timestamps
	now := time.Unix(0, Now)
	timestamps := make([]time.Time, numTests)
	for i := 0; i < numTests; i++ {
		timestamps[i] = time.Unix(0, UnixNanoTimestamps[i])
	}

	// use insecure seeded rng to ensure repeatability
	notRand := &CountingReader{count: uint8(0)}

	// Generate signatures and verify them
	for i := 0; i < numTests; i++ {
		// Generate bad, random verification signature
		verifSig := make([]byte, 32)
		notRand.Read(verifSig)

		// Sign upload signatures
		uploadSig, err := SignUpload(notRand, receptionKeys[i], files[i], timestamps[i])
		if err != nil {
			t.Fatalf("Failed to generate upload sig "+
				"%d/%d: %v", i, numTests, err)
		}

		//try to verify the signature
		fileHash, err := HashFile(files[i])
		if err != nil {
			t.Fatalf("Failed to has file %d/%d: %v", i, numTests, err)
		}

		if err = JointVerify(UDPrivKey.GetPublic(), receptionKeys[i].GetPublic(),
			HashUsername(Usernames[i]), fileHash, verifSig, uploadSig,
			timestamps[i], now); err == nil {
			t.Fatalf("Joint Verification succeded with bad verification "+
				"signature %d/%d: %v", i, numTests, err)
		}
	}
}

func TestJointVerify_BadUploadSig(t *testing.T) {

	UDPrivKey, err := rsa.LoadPrivateKeyFromPem([]byte(PrivKeyPemEncoded))
	if err != nil {
		t.Fatalf("Failed to load private key: %v", err)
	}

	// Process reception keys
	receptionKeys := make([]*rsa.PrivateKey, numTests)
	for i := 0; i < numTests; i++ {
		receptionKeys[i], err = rsa.LoadPrivateKeyFromPem([]byte(ReceptionKeys[i]))
		if err != nil {
			t.Fatalf("Failed to decode reception key %d/%d: %v",
				i, numTests, err)
		}

	}

	// Process files
	files := make([][]byte, numTests)
	for i := 0; i < numTests; i++ {
		files[i], err = base64.StdEncoding.DecodeString(Files[i])
		if err != nil {
			t.Fatalf("Failed to parse file: %v", err)
		}
	}

	// Process timestamps
	now := time.Unix(0, Now)
	timestamps := make([]time.Time, numTests)
	for i := 0; i < numTests; i++ {
		timestamps[i] = time.Unix(0, UnixNanoTimestamps[i])
	}

	// use insecure seeded rng to ensure repeatability
	notRand := &CountingReader{count: uint8(0)}

	// Generate signatures and verify them
	for i := 0; i < numTests; i++ {
		// Sign verification signature
		verifSig, err := SignVerification(notRand, UDPrivKey,
			Usernames[i], receptionKeys[i].GetPublic())
		if err != nil {
			t.Fatalf("Failed to generate verification sig %d/%d: "+
				"%v", i, numTests, err)
		}

		// Sign upload signatures
		uploadSig := make([]byte, 32)
		notRand.Read(uploadSig)

		//try to verify the signature
		fileHash, err := HashFile(files[i])
		if err != nil {
			t.Fatalf("Failed to has file %d/%d: %v", i, numTests, err)
		}

		if err = JointVerify(UDPrivKey.GetPublic(), receptionKeys[i].GetPublic(),
			HashUsername(Usernames[i]), fileHash, verifSig, uploadSig,
			timestamps[i], now); err == nil {
			t.Fatalf("Joint Verification failed %d/%d: %v", i, numTests, err)
		}
	}
}
