///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package singleUse

import (
	"encoding/base64"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/diffieHellman"
	"gitlab.com/elixxir/primitives/format"
	"math/rand"
	"testing"
)

// Tests that the generated fingerprints do not change.
func TestNewResponseFingerprint_Consistency(t *testing.T) {
	expectedFPs := []string{
		"OrMBolBbKdrbOYgzErZekpk4EZkoJ+rnM1NDq86aPVs=",
		"KO7Ri01TBy45IQY2P21R4BAe6GAYQu86tP5JYIlkkeU=",
		"KgSF7wk/VBx506dgR2DygKoCXLCErjxWHc6WoGqe5eQ=",
		"OXP6eKBx/pvU6WEZW9vQPq8IcaYHBzLow8zUDtXaJGQ=",
		"c/E2DCT3iCnOVDV2kBTe2BwbxsiR9dH6ImB8oPS3nFo=",
		"NS/WmbI3gdwBY0qfoNt+OKavi+TFYy0GKcAXtV0gIuo=",
		"fuJQu0DiFIImUYYILEtw3Jw5iFs9z/L+32RujfTVoRo=",
		"LvMcRLC2XTPaV5PuRJ2RTJrQTy6L0I+FwboSLiRYnfM=",
		"ZUpBiFwcfM/Geae5nyoDVvb3fgkIbZD1HlfTfN19PYI=",
		"SW7r5m5FuOY/hkEr/d4ze+0RJa9iXf3xRzvyUtyL6yY=",
	}
	prng := rand.New(rand.NewSource(42))

	for i, expectedFP := range expectedFPs {
		privKey := diffieHellman.GeneratePrivateKey(
			diffieHellman.DefaultPrivateKeyLength, getGrp(), prng)
		pubKey := diffieHellman.GeneratePublicKey(privKey, getGrp())
		dhKey := diffieHellman.GenerateSessionKey(privKey, pubKey, getGrp())

		testFP := NewResponseFingerprint(dhKey, uint64(i))
		testFpBase64 := base64.StdEncoding.EncodeToString(testFP[:])

		if expectedFP != testFpBase64 {
			t.Errorf("NewResponseFingerprint did not return the expected "+
				"fingerprint (%d).\nexpected: %s\nreceived: %s",
				i, expectedFP, testFpBase64)
		}
	}
}

// Tests that all generated fingerprints are unique.
func TestNewResponseFingerprint_Unique(t *testing.T) {
	testRuns := 20
	prng := rand.New(rand.NewSource(42))
	FPs := make(map[format.Fingerprint]struct {
		dhKey  *cyclic.Int
		keyNum uint64
	})

	// Test with same DH key but differing key numbers
	for i := 0; i < testRuns; i++ {
		privKey := diffieHellman.GeneratePrivateKey(
			diffieHellman.DefaultPrivateKeyLength+i, getGrp(), prng)
		pubKey := diffieHellman.GeneratePublicKey(privKey, getGrp())
		dhKey := diffieHellman.GenerateSessionKey(privKey, pubKey, getGrp())
		for j := 0; j < testRuns; j++ {
			testFP := NewResponseFingerprint(dhKey, uint64(j))

			if _, exists := FPs[testFP]; exists {
				t.Errorf("Generated fingerprint collides with previously "+
					"generated fingerprint (%d, %d)."+
					"\ncurrent FP:   dhKey: %s  keyNum: %d"+
					"\npreviouse FP: dhKey: %s  keyNum: %d"+
					"\nFP:           %s", i, j,
					dhKey.Text(10), j, FPs[testFP].dhKey.Text(10),
					FPs[testFP].keyNum, testFP)
			} else {
				FPs[testFP] = struct {
					dhKey  *cyclic.Int
					keyNum uint64
				}{dhKey, uint64(j)}
			}
		}
	}

	// Test with same key numbers but differing DH keys
	for i := 0; i < testRuns; i++ {
		for j := 0; j < testRuns; j++ {
			privKey := diffieHellman.GeneratePrivateKey(
				diffieHellman.DefaultPrivateKeyLength+j, getGrp(), prng)
			pubKey := diffieHellman.GeneratePublicKey(privKey, getGrp())
			dhKey := diffieHellman.GenerateSessionKey(privKey, pubKey, getGrp())
			testFP := NewResponseFingerprint(dhKey, uint64(i))

			if _, exists := FPs[testFP]; exists {
				t.Errorf("Generated fingerprint collides with previously "+
					"generated fingerprint (%d, %d)."+
					"\ncurrent FP:   dhKey: %s  keyNum: %d"+
					"\npreviouse FP: dhKey: %s  keyNum: %d"+
					"\nFP:           %s", i, j,
					dhKey.Text(10), i, FPs[testFP].dhKey.Text(10),
					FPs[testFP].keyNum, testFP)
			} else {
				FPs[testFP] = struct {
					dhKey  *cyclic.Int
					keyNum uint64
				}{dhKey, uint64(i)}
			}
		}
	}
}
