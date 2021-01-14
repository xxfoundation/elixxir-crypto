///////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                          //
//                                                                           //
// Use of this source code is governed by a license that can be found in the //
// LICENSE file                                                              //
///////////////////////////////////////////////////////////////////////////////

package singleUse

import (
	"encoding/base64"
	"gitlab.com/elixxir/crypto/diffieHellman"
	"math/rand"
	"testing"
)

// Tests that the generated key does not change.
func TestResponseKey(t *testing.T) {
	expectedKey := "6H61xTtJZYhmT8Q2cm3ZXj7J95yHO5lQN/s1cRu/j40="
	grp := getGrp()
	prng := rand.New(rand.NewSource(42))

	pubKey := diffieHellman.GeneratePublicKey(diffieHellman.GeneratePrivateKey(
		diffieHellman.DefaultPrivateKeyLength, grp, prng), grp)
	testKey := ResponseKey(pubKey, 0)
	testKeyBase64 := base64.StdEncoding.EncodeToString(testKey)

	if expectedKey != testKeyBase64 {
		t.Errorf("ResponseKey() did not return the expected key for public "+
			"key %s.\nexpected: %s\nreceived: %s",
			pubKey.Text(10), expectedKey, testKeyBase64)
	}
}
