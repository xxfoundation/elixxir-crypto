////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package fileTransfer

import (
	"encoding/base64"
	"math/rand"
	"testing"
)

// Consistency test: tests that CreateTransferMAC returns the expected values.
// If the expected values no longer match, then some underlying dependency has
// made a potentially breaking change.
func TestCreateTransferMAC_Consistency(t *testing.T) {
	expectedTransferMACs := []string{
		"VjTOTyOPmCHTZsrvZReG6TwO/mWqVE8vwOW91fissxw=",
		"W+m5leqDbs7Gn4rAsRrsD/+V4UyHrGiOvQ+wSFBOkqw=",
		"C7xtdNVFEDpeTtTe5YkUgGTpuDjATslDUC8Qci0ssIQ=",
		"ckv3McxJQWp+tpbnVHwoHvmQvXs7Tr3USZngT3g//Ss=",
	}

	// Construct a deterministic PRNG for testing
	prng := rand.New(rand.NewSource(42))

	// Generate all data needed for MAC generation
	for i, expected := range expectedTransferMACs {
		// Generate random transfer key
		var transferKey TransferKey
		prng.Read(transferKey[:])

		// Generate random message payload
		msgPayload := make([]byte, 128)
		prng.Read(msgPayload)

		// Generate MAC
		mac := CreateTransferMAC(msgPayload, transferKey)

		// Base64 encode the MAC for comparison
		mac64 := base64.StdEncoding.EncodeToString(mac)

		// Check if generated MAC matches expected value
		if mac64 != expected {
			t.Errorf("New transfer MAC #%d does not match expected."+
				"\nexpected: %s\nreceived: %s", i, expected, mac64)
		}

		// Ensure the first bit is zero
		if mac[0]>>7 != 0 {
			t.Errorf("First bit of MAC #%d is not 0."+
				"\nexpected: %d\nreceived: %d", i, 0, mac[0]>>7)
		}
	}
}

// Tests that VerifyTransferMAC correctly verifies the generated MACs.
func TestVerifyTransferMAC(t *testing.T) {
	// Construct a deterministic prng for testing
	prng := rand.New(rand.NewSource(42))

	numTries := 100

	// Generate all data needed for MAC generation
	for i := 0; i < numTries; i++ {
		// Generate random transfer key
		var transferKey TransferKey
		prng.Read(transferKey[:])

		// Generate random message payload
		msgPayload := make([]byte, 128)
		prng.Read(msgPayload)

		// Generate MAC
		mac := CreateTransferMAC(msgPayload, transferKey)

		// Check if generated MAC matches expected value
		if !VerifyTransferMAC(msgPayload, transferKey, mac) {
			t.Errorf("MAC could not be verified at index %d.", i)
		}
	}
}

// Error path: tests that VerifyTransferMAC does not verify different MACs.
func TestVerifyTransferMAC_BadMacError(t *testing.T) {
	// Construct a deterministic prng for testing
	prng := rand.New(rand.NewSource(42))

	numTries := 100

	// Generate all data needed for MAC generation
	for i := 0; i < numTries; i++ {
		// Generate random transfer key
		var transferKey TransferKey
		prng.Read(transferKey[:])

		// Generate random message payload
		msgPayload := make([]byte, 128)
		prng.Read(msgPayload)

		// Generate an invalid MAC
		badMac := make([]byte, 32)
		prng.Read(badMac)

		// Check if generated MAC matches expected value
		if VerifyTransferMAC(msgPayload, transferKey, badMac) {
			t.Errorf("Invalid MAC was verified at index %d.", i)
		}
	}
}

// Consistency test: tests that createPartMAC returns the expected values. If
// the expected values no longer match, then some underlying dependency has made
// a potentially breaking change.
func Test_createPartMAC_Consistency(t *testing.T) {
	expectedMessageMACs := []string{
		"B/2L77dMU5QmoSEyhz9/JIjSezj1bmjb9b6d5iQPt0E=",
		"YYrFtOitkyaf1sIYHf5zlBR/kpKS2HPPP6azWdriwgE=",
		"IDwozKX8l/eZkkEDHGrWDvlUaVTQaoNFy9f1u7KlYHM=",
		"eXlpn2e1By/q/pxWtW5jMJNNvjAQ+gxC2YI38hCvo3g=",
	}

	// Construct a deterministic prng for testing
	prng := rand.New(rand.NewSource(42))

	// Generate all data needed for MAC generation
	for i, expected := range expectedMessageMACs {
		// Create random file part key
		var partKey partKey
		prng.Read(partKey[:])

		// Generate random padding
		padding := make([]byte, 8)
		prng.Read(padding)

		// Generate random message payload
		msgPayload := make([]byte, 128)
		prng.Read(msgPayload)

		// Generate the file part MAC
		mac := createPartMAC(padding, msgPayload, partKey)

		// Base64 encode the MAC for comparison
		mac64 := base64.StdEncoding.EncodeToString(mac)

		// Check if generated MAC matches expected value
		if expected != mac64 {
			t.Errorf("New part MAC #%d does not match expected."+
				"\nexpected: %s\nreceived: %s", i, expected, mac64)
		}

		// Ensure the first bit is zero
		if mac[0]>>7 != 0 {
			t.Errorf("First bit of MAC #%d is not 0."+
				"\nexpected: %d\nreceived: %d", i, 0, mac[0]>>7)
		}
	}
}

// Tests that verifyPartMAC correctly verifies the generated MACs.
func Test_verifyPartMac(t *testing.T) {
	// Construct a deterministic prng for testing
	prng := rand.New(rand.NewSource(42))

	numTries := 100

	// Generate all data needed for MAC generation
	for i := 0; i < numTries; i++ {
		// Generate random file part key
		var partKey partKey
		prng.Read(partKey[:])

		// Generate random nonce
		nonce := make([]byte, 8)
		prng.Read(nonce)

		// Generate random message payload
		msgPayload := make([]byte, 128)
		prng.Read(msgPayload)

		// Generate MAC
		mac := createPartMAC(nonce, msgPayload, partKey)

		// Check if generated MAC matches expected value
		if !verifyPartMAC(nonce, msgPayload, mac, partKey) {
			t.Errorf("MAC could not be verified at index %d.", i)
		}
	}
}

// Error path: tests that verifyPartMAC does not verify different MACs.
func Test_verifyPartMAC_BadMacError(t *testing.T) {
	// Construct a deterministic prng for testing
	prng := rand.New(rand.NewSource(42))

	numTries := 100

	// Generate all data needed for MAC generation
	for i := 0; i < numTries; i++ {
		// Generate random file part key
		var partKey partKey
		prng.Read(partKey[:])

		// Generate random nonce
		nonce := make([]byte, 8)
		prng.Read(nonce)

		// Generate random message payload
		msgPayload := make([]byte, 128)
		prng.Read(msgPayload)

		// Generate an invalid MAC
		badMac := make([]byte, 32)
		prng.Read(badMac)

		// Check if generated MAC matches expected value
		if verifyPartMAC(nonce, msgPayload, badMac, partKey) {
			t.Errorf("Invalid MAC was verified at index %d.", i)
		}
	}
}
