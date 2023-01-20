////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package singleUse

import (
	"encoding/base64"
	"gitlab.com/elixxir/crypto/diffieHellman"
	"gitlab.com/xx_network/crypto/cyclic"
	"math/rand"
	"testing"
)

// Tests that the generated key does not change.
func TestNewRequestPartKey_Consistency(t *testing.T) {
	expectedKeys := []string{
		"8XtqywBq3DkBgaNaMKL+kOlRtvqIbrVM/uqNR9RzOXY=",
		"GbjOauzOwLkRmfXf20tzS8lI2SDB2axUpeTwm5cuZ+I=",
		"+dD0KPb1mXqa3PwC1lKnl3CpFtBd8pkue+Rc8ldNUHo=",
		"C+iAEWU9+UEN9qlPddc2N/Y+tz1j4+ESy6j69kdhvbU=",
		"X0SKzdhUTprC7I7QhbHO/sfK29fPHoRyGnKv2TQtCzE=",
		"g71Vjy5LyyHmC2d2rIqtQdACmUlmh2QB/sifsJn+xxg=",
		"pXbguTkf+8xQ5u3Vv8PsG492HX+SloxbYmyarJZf9cY=",
		"/4vreuoOfvFQXKCD+23MuZHuiwHUvpqua5F07Hwa6zw=",
		"YuDVXt+BiBOBnLSLAgKytGLkdXrR6zMlJ+CWQ+b2lg0=",
		"F/TNYF1lPR9uxk4TIHVzSOzFbizautINZmzUKb43P3k=",
	}
	prng := rand.New(rand.NewSource(42))

	for i, expectedKey := range expectedKeys {
		privKey := diffieHellman.GeneratePrivateKey(
			diffieHellman.DefaultPrivateKeyLength, getGrp(), prng)
		pubKey := diffieHellman.GeneratePublicKey(privKey, getGrp())
		dhKey := diffieHellman.GenerateSessionKey(privKey, pubKey, getGrp())

		testKey := NewRequestPartKey(dhKey, uint64(i))
		testKeyBase64 := base64.StdEncoding.EncodeToString(testKey)

		if expectedKey != testKeyBase64 {
			t.Errorf("NewRequestPartKey did not return the expected key (%d)."+
				"\nexpected: %s\nreceived: %s", i, expectedKey, testKeyBase64)
		}
	}
}

// Tests that all generated keys are unique.
func TestNewRequestPartKey_Unique(t *testing.T) {
	testRuns := 20
	prng := rand.New(rand.NewSource(42))
	keys := make(map[string]struct {
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
			testKey := NewRequestPartKey(dhKey, uint64(j))
			testKeyBase64 := base64.StdEncoding.EncodeToString(testKey)

			if _, exists := keys[testKeyBase64]; exists {
				t.Errorf("Generated key collides with previously generated "+
					"key (%d, %d)."+
					"\ncurrent key:   dhKey: %s  keyNum: %d"+
					"\npreviouse key: dhKey: %s  keyNum: %d"+
					"\nkey:           %s", i, j,
					dhKey.Text(10), j, keys[testKeyBase64].dhKey.Text(10),
					keys[testKeyBase64].keyNum, testKeyBase64)
			} else {
				keys[testKeyBase64] = struct {
					dhKey  *cyclic.Int
					keyNum uint64
				}{dhKey, uint64(j)}
			}
		}
	}

	// Test with same key number but differing DH keys
	for i := 0; i < testRuns; i++ {
		for j := 0; j < testRuns; j++ {
			privKey := diffieHellman.GeneratePrivateKey(
				diffieHellman.DefaultPrivateKeyLength+j, getGrp(), prng)
			pubKey := diffieHellman.GeneratePublicKey(privKey, getGrp())
			dhKey := diffieHellman.GenerateSessionKey(privKey, pubKey, getGrp())
			testKey := NewRequestPartKey(dhKey, uint64(i))
			testKeyBase64 := base64.StdEncoding.EncodeToString(testKey)

			if _, exists := keys[testKeyBase64]; exists {
				t.Errorf("Generated key collides with previously generated "+
					"key (%d, %d)."+
					"\ncurrent key:   dhKey: %s  keyNum: %d"+
					"\npreviouse key: dhKey: %s  keyNum: %d"+
					"\nkey:           %s", i, j,
					dhKey.Text(10), i, keys[testKeyBase64].dhKey.Text(10),
					keys[testKeyBase64].keyNum, testKeyBase64)
			} else {
				keys[testKeyBase64] = struct {
					dhKey  *cyclic.Int
					keyNum uint64
				}{dhKey, uint64(i)}
			}
		}
	}
}
