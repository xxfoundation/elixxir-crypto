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

// Tests that the generated fingerprints do not change.
func TestResponseFingerprint(t *testing.T) {
	expectedFP := "H+GySzAGq3y6o1JA0Mqxn68GO1uSzCEmpVVbHR2sJc8="
	grp := getGrp()
	prng := rand.New(rand.NewSource(42))

	dhKey := diffieHellman.GeneratePublicKey(diffieHellman.GeneratePrivateKey(
		diffieHellman.DefaultPrivateKeyLength, grp, prng), grp)
	testFP := ResponseFingerprint(dhKey, 0)
	testFPb64 := base64.StdEncoding.EncodeToString(testFP[:])

	if expectedFP != testFPb64 {
		t.Errorf("ResponseFingerprint() did not return the expected "+
			"fingerprint for public key %s."+
			"\nexpected: %s\nreceived: %s",
			dhKey.Text(10), expectedFP, testFPb64)
	}
}

// Tests that the generated fingerprints do not change.
func Test_makeHash_Consistency(t *testing.T) {
	expectedHashes := []string{
		"R7UL7by0fP2bXRBlzUOrUKo+7pRATF4r6bUD8/H+PBc=",
		"CQsWbxgdjYOIJsdfTk/w3549Ltp7TJlSUquK94O8rAM=",
		"5+pY4khsqHh0bEXZvYC2DLEJbxq4g5bL19JsllOcfso=",
		"FW9gcwJAl90cLcsnxdnHLcIuJO6NpXqkVWFfbXqWXmA=",
		"peyTwZZUKPwHB5J1UptEbL+TUEjvg4ZBVceE/J1Q3pQ=",
		"f8YCUyFXznRHQ1gzuBJrSQegE7wC1JYb8MPTbtJ+qj0=",
		"g6pHsrATAkSl7QMn9Re01nuc5VF88yvyWvPCHKm3upk=",
		"S0WrlEhrMIDvJ68hhY6c0Mk5FabZqoAoUdxaBrDXdhg=",
		"2mHHoyjQExs314tLMg+6pt1cGE5j4vckWZa18pPjZmQ=",
		"2YMO0HeFF6dCd3cKhNQAXw76zaQ573fw0TM/3PLmUGI=",
	}
	grp := getGrp()
	prng := rand.New(rand.NewSource(42))

	for i, expectedHash := range expectedHashes {
		dhKey := diffieHellman.GeneratePublicKey(diffieHellman.GeneratePrivateKey(
			diffieHellman.DefaultPrivateKeyLength, grp, prng), grp)
		testHash := makeKeyHash(dhKey, uint64(i), "constant")
		testHashBase64 := base64.StdEncoding.EncodeToString(testHash)

		if expectedHash != testHashBase64 {
			t.Errorf("makeHash() did not return the expected hash for public "+
				"key %s at index %d.\nexpected: %s\nreceived: %s",
				dhKey.Text(10), i, expectedHash, testHashBase64)
		}
	}
}

// Tests that all generated fingerprints are unique.
func Test_makeHash_Unique(t *testing.T) {
	grp := getGrp()
	prng := rand.New(rand.NewSource(42))
	hashes := make(map[string]*cyclic.Int, 100)

	for i := 0; i < 100; i++ {
		dhKey := diffieHellman.GeneratePublicKey(diffieHellman.GeneratePrivateKey(
			diffieHellman.DefaultPrivateKeyLength, grp, prng), grp)
		testHash := makeKeyHash(dhKey, uint64(i), "constant")

		hashBase64 := base64.StdEncoding.EncodeToString(testHash)

		if hashes[hashBase64] != nil {
			t.Errorf("Generated hash from key %s collides with "+
				"previously generated hash from key %s.\nfingerprint: %s",
				dhKey.Text(10), hashes[hashBase64].Text(10), hashBase64)
		} else {
			hashes[hashBase64] = dhKey
		}
	}
}
