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
func TestNewTransmitKey_Consistency(t *testing.T) {
	expectedKeys := []string{
		"4/q8XevjJmz2ectxCr/NseWS9cSzVD/SUW36m/gk5iA=",
		"zdF5z3ouPBE1LX8HGuKmlif9QXoURoB8SYvJ/hmrD78=",
		"kWfO8yo6AXWsfWlo5hZGFei/MdU6kjQO/Q5+tW8CH6A=",
		"fFnJJTooPyT489Z6DDmXviKvO3ANO/go+SK9bsw47J8=",
		"ea0K4bAH6j6svv62OF0/xck/V6fsHAzGqK3+gYshfsY=",
		"L8YsjbsdUcOjYTthWDXDDD0GwizPxCMtkuYOSdNEvxw=",
		"zcJiH/vhbj9fGwp1FIIqdTwU9zwgLC1vv13NKjpznUc=",
		"9Tg08QAHOcPR9HmPmKOTkMetLdGYF16VJ0NT62o93aQ=",
		"8ky3KxQGlf6+6W/XZd8hV++sfMFdiTDI+XGMJXGck/A=",
		"Jzz96sW79uil/WCnY+8wgH5fDstCbKGs+H7Fd5+olW8=",
	}
	prng := rand.New(rand.NewSource(42))

	for i, expectedKey := range expectedKeys {
		privKey := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength, getGrp(), prng)
		pubKey := diffieHellman.GeneratePublicKey(privKey, getGrp())
		dhKey := diffieHellman.GenerateSessionKey(privKey, pubKey, getGrp())

		testKey := NewTransmitKey(dhKey)
		testKeyBase64 := base64.StdEncoding.EncodeToString(testKey)

		if expectedKey != testKeyBase64 {
			t.Errorf("NewTransmitKey() did not return the expected key (%d)."+
				"\nexpected: %s\nreceived: %s", i, expectedKey, testKeyBase64)
		}
	}
}

// Tests that all generated keys are unique.
func TestNewTransmitKey_Unique(t *testing.T) {
	testRuns := 20
	prng := rand.New(rand.NewSource(42))
	keys := make(map[string]*cyclic.Int, 100)

	for i := 0; i < testRuns; i++ {
		privKey := diffieHellman.GeneratePrivateKey(diffieHellman.DefaultPrivateKeyLength, getGrp(), prng)
		pubKey := diffieHellman.GeneratePublicKey(privKey, getGrp())
		dhKey := diffieHellman.GenerateSessionKey(privKey, pubKey, getGrp())

		testKey := base64.StdEncoding.EncodeToString(NewTransmitKey(dhKey))

		if keys[testKey] != nil {
			t.Errorf("Generated fingerprint from key %s collides with "+
				"previously generated fingerprint from key %s.\nfingerprint: %s",
				dhKey.Text(10), keys[testKey].Text(10), testKey)
		} else {
			keys[testKey] = dhKey
		}
	}
}
