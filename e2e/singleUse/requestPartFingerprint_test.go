////////////////////////////////////////////////////////////////////////////////
// Copyright © 2024 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

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
func TestNewRequestPartFingerprint_Consistency(t *testing.T) {
	expectedFPs := []string{
		"PaTmC4OhL7KbVlkNIJicM4Sn9GU3bMKCPzJSlkxjG5w=",
		"RwI/482PG2ACCCBkxLB7+F7C/ACoZV+7fCWOlGiCDug=",
		"NHLoiQv/Yk/0n/yhkE2qoSrFd/xbLJHoLMZ4mObR7Bs=",
		"QfA79KzBVFpK7fwpZ4+47qoNTmDysqgRI+20DMaGAxU=",
		"Zw+9I09LbCth9V1MQtrfv0JyzJvi8ofTfzH77CLTRpg=",
		"cYBGtTn2H72Iw/5L6uHuvx92f328cmx2WPMo1r80o5s=",
		"f4dYVtCFDYg4b7CVShUFOQxDeZvENdBttQG1MuXmWL8=",
		"NiJ9VBoQcex8kYj+1nZHmN/zo4TxcVtCA6ZDPB2jV88=",
		"DK1W7deW13Es2tRwOvCx8W9anMvghj1ciXriKMfZyJk=",
		"CK5iflM/XDHfhtRjYam3itcdqOnmyonAntJQyF4z4IY=",
	}
	prng := rand.New(rand.NewSource(42))

	for i, expectedFP := range expectedFPs {
		privKey := diffieHellman.GeneratePrivateKey(
			diffieHellman.DefaultPrivateKeyLength, getGrp(), prng)
		pubKey := diffieHellman.GeneratePublicKey(privKey, getGrp())
		dhKey := diffieHellman.GenerateSessionKey(privKey, pubKey, getGrp())

		testFP := NewRequestPartFingerprint(dhKey, uint64(i))
		testFpBase64 := base64.StdEncoding.EncodeToString(testFP[:])

		if expectedFP != testFpBase64 {
			t.Errorf("NewRequestPartFingerprint did not return the expected "+
				"fingerprint (%d).\nexpected: %s\nreceived: %s",
				i, expectedFP, testFpBase64)
		}
	}
}

// Tests that all generated fingerprints are unique.
func TestNewRequestPartFingerprint_Unique(t *testing.T) {
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
			testFP := NewRequestPartFingerprint(dhKey, uint64(j))

			if _, exists := FPs[testFP]; exists {
				t.Errorf("Generated fingerprint collides with previously "+
					"generated fingerprint (%d, %d)."+
					"\ncurrent FP:   dhKey: %s  keyNum: %d"+
					"\npreviouse FP: dhKey: %s  keyNum: %d"+
					"\nfingerprint:  %s", i, j, dhKey.Text(10), j,
					FPs[testFP].dhKey.Text(10), FPs[testFP].keyNum, testFP)
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
			testFP := NewRequestPartFingerprint(dhKey, uint64(i))

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
