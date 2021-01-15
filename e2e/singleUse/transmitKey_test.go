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
	"math/rand"
	"testing"
)

// Tests that the generated keys do not change.
func TestTransmitKey_Consistency(t *testing.T) {
	expectedKeys := []string{
		"r8w70j5FjEcdt8xlpJl4eQxIem+UMrpXt5K/JYhXj2g=",
		"0FVEW60pQRTgfZXhn+wRa+PqPSAM9vMCH1YjRYUoi9s=",
		"aIhJ7Oy0/1uIz3PPme4KOVrPf4VIpQ7iUj3DZ0iTDEg=",
		"iZZphXY4wO55I8Y3T83vdfvzowjT8Kfvm66QtvZ9lmE=",
		"zMmiCDe7d8mFDJvXrBmv81UXWB2fPZMzcPScUaLuvos=",
		"HvdofUNn/dRIPnXyre0naqnrWNEO8Fa5XiXFzHgR2SY=",
		"D72jZPNZ7NwS+y00yaT2jwX8e+8WXJFsIMp7DX1eIG0=",
		"pfhnc3jF/c52OG9BQIbRCaUluyAPgz1+M/TUVigbi44=",
		"F4Xlmu/ceaAOcXjM9gqhr4uG4q0l6u+tHG34xjaeNFM=",
		"njlwVRA/zIER7c4znROHKaswUNktB4z7L9MLa3bcjnY=",
	}
	grp := getGrp()
	prng := rand.New(rand.NewSource(42))

	for i, expected := range expectedKeys {
		dhKey := diffieHellman.GeneratePublicKey(diffieHellman.GeneratePrivateKey(
			diffieHellman.DefaultPrivateKeyLength, grp, prng), grp)
		testKey := base64.StdEncoding.EncodeToString(TransmitKey(dhKey))

		if expected != testKey {
			t.Errorf("TransmitKey() did not return the expected key "+
				"for public key %s at index %d.\nexpected: %s\nreceived: %s",
				dhKey.Text(10), i, expected, testKey)
		}
	}
}

// Tests that all generated keys are unique.
func TestTransmitKey_Unique(t *testing.T) {
	grp := getGrp()
	prng := rand.New(rand.NewSource(42))
	keys := make(map[string]*cyclic.Int, 100)

	for i := 0; i < 100; i++ {
		dhKey := diffieHellman.GeneratePublicKey(diffieHellman.GeneratePrivateKey(
			diffieHellman.DefaultPrivateKeyLength, grp, prng), grp)
		testKey := base64.StdEncoding.EncodeToString(TransmitKey(dhKey))

		if keys[testKey] != nil {
			t.Errorf("Generated fingerprint from key %s collides with "+
				"previously generated fingerprint from key %s.\nfingerprint: %s",
				dhKey.Text(10), keys[testKey].Text(10), testKey)
		} else {
			keys[testKey] = dhKey
		}
	}
}
