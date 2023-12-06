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
	"math/rand"
	"testing"
)

// Tests that the generated key does not change.
func TestNewResponseKey_Consistency(t *testing.T) {
	expectedKeys := []string{
		"gMv3mjIgCpTgqx/1d0+k3jYlfkPTM2DtOGYzUKGHwK4=",
		"k5E9tfudE5W8APDNvZ9XfHuxuivsefcP3IhOBACh7Mg=",
		"iqQrsHI7bmJGxqHC6bUqXgt03VeGSHHSRBGZ0RrEvP8=",
		"+taXBcQ+4IB00gvkjQXia6Y6BJJ05vYaO2Ou+8yTd+M=",
		"PiaH5qrVUdRCKwyf2Kic/M8rqm+q4UNvoVmFFI51k8Y=",
		"jpKUMoteRvQVJnDsTi4pjw0XL5P4U5rhWaK+0RaKVVw=",
		"2zx20KGB9xBObQ8cwF3FzpCwApiV8Du/FL2+Ykmh/ck=",
		"hVYAGYQtd3x0FgXuavULI8saisTjs4rJamebd5aNzQ8=",
		"zN+Cl7h5KvFGcGPLUVZ0Qjiws5LNUXXhuDUUw6osSfU=",
		"MVzZoMffLm7Bi7XAuOZxYFxAzeNqxUAG6kZCSCKJuDE=",
	}
	prng := rand.New(rand.NewSource(42))

	for i, expectedKey := range expectedKeys {
		privKey := diffieHellman.GeneratePrivateKey(
			diffieHellman.DefaultPrivateKeyLength, getGrp(), prng)
		pubKey := diffieHellman.GeneratePublicKey(privKey, getGrp())
		dhKey := diffieHellman.GenerateSessionKey(privKey, pubKey, getGrp())

		testKey := NewResponseKey(dhKey, uint64(i))
		testKeyBase64 := base64.StdEncoding.EncodeToString(testKey)

		if expectedKey != testKeyBase64 {
			t.Errorf("NewResponseKey did not return the expected key (%d)."+
				"\nexpected: %s\nreceived: %s", i, expectedKey, testKeyBase64)
		}
	}
}

// Tests that all generated keys are unique.
func TestNewResponseKey_Unique(t *testing.T) {
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
			testKey := NewResponseKey(dhKey, uint64(j))
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
			testKey := NewResponseKey(dhKey, uint64(i))
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
