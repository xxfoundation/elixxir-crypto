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
func TestNewTransmitFingerprint_Consistency(t *testing.T) {
	expectedFPs := []string{
		"Esl9VY4LNOmXqmmEpZfu0Koo/++Zqx/vDSqBFFpdvjI=",
		"ASz49SEnYLLW7KkVLbHJiYOAlkkY1r/AJBHaR2s1UDk=",
		"ZxN1S6SBESGAB+2LpKQv18rXqVtwANe19AK2dXckpiM=",
		"CNZUU0N7gmkjg+/rCZZaZz3NNfLA8zQychvFuhdBa6s=",
		"blMhqREthbMo9HInS4gq85k4oLOq4L5WlT+U1yFGfYQ=",
		"b//RiQzsN1BG6pYufzZFmRyrkHP5f4+GaYIutfUZlNw=",
		"VRbcFvAMFf8SvYLGf2aL9jlenwNG45BzZbuhFbrOZ9Y=",
		"TiQPO2mHY4Qv/Kr+jqMDiokIWoE6HSn5exlwQw7iK+Y=",
		"NG21WIBMqCTB4zZAb6CWvQ+B0080zh5e4BQ9Xzh52cI=",
		"TrA7y8S2NayhqYWPyZDs5q+rC+mlo/CXBt3P6bsmGwQ=",
	}
	prng := rand.New(rand.NewSource(42))

	for i, expectedFP := range expectedFPs {
		privKey := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength, getGrp(), prng)
		pubKey := diffieHellman.GeneratePublicKey(privKey, getGrp())

		testFP := NewTransmitFingerprint(pubKey)
		testFpBase64 := base64.StdEncoding.EncodeToString(testFP[:])

		if expectedFP != testFpBase64 {
			t.Errorf("NewTransmitFingerprint() did not return the expected "+
				"fingerprint (%d).\nexpected: %s\nreceived: %s",
				i, expectedFP, testFpBase64)
		}
	}
}

// Tests that all generated fingerprints are unique.
func TestNewTransmitFingerprint_Unique(t *testing.T) {
	testRuns := 20
	prng := rand.New(rand.NewSource(42))
	FPs := make(map[format.Fingerprint]*cyclic.Int)

	for i := 0; i < testRuns; i++ {
		privKey := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength, getGrp(), prng)
		pubKey := diffieHellman.GeneratePublicKey(privKey, getGrp())
		testFP := NewTransmitFingerprint(pubKey)

		if FPs[testFP] != nil {
			t.Errorf("Generated fingerprint from key %s collides with "+
				"previously generated fingerprint from key %s."+
				"\nfingerprint: %s", pubKey.Text(10), FPs[testFP].Text(10),
				testFP)
		} else {
			FPs[testFP] = pubKey
		}
	}
}
