package broadcast

import (
	"encoding/base64"
	"gitlab.com/elixxir/primitives/format"
	"math/rand"
	"testing"
)

// Tests consistency of newMessageKey.
func Test_newMessageKey_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	expectedSalts := []string{
		"WJv/ImXt3M8N8XdhYIaIavMUCRbrsugsGhtz59h57mA=",
		"rdbxfPJwGtKHG2+3Zg/Wtv5iUNTC9JuFnaDrKFv+1gE=",
		"xWJsW5g8/sIW+QwH1FtOkX1ocKJBohhqa9m2jWtjyiI=",
		"t2ZODDpCpbUvHsgEpgBh+FhfoI5oYGx1zF65lP+jUbk=",
		"ptxLzNAdGsgIECTh/6rcbptch3EtACJaTMIM/zTR/rw=",
		"v6cpgc1vGye220ALLZVf5Z2rXGik6EtV1SWLcQaxicY=",
		"T1Ws2CW+YluHf+9r+ytGfrb+h/OhUWKyasGt9OvNeLw=",
		"O2kZ1j48UGfr8MmRP0/GyNUrsjfYa966JkSe/VL6Zx0=",
		"bVE5e2HfcbNL4iFYQ9XGUU3jD4WZvXLmxqXZRvgf+ZI=",
		"h8KQkXwif6ElOwSfkbmCRtLKR6mq5+uyb1T4E/4z4Zs=",
	}

	for i, expected := range expectedSalts {
		var nonce format.Fingerprint
		prng.Read(nonce[:])
		symKey := make([]byte, 16)
		prng.Read(symKey)

		key := newMessageKey(nonce, symKey)
		keyStr := base64.StdEncoding.EncodeToString(key)

		if expected != keyStr {
			t.Errorf("Message key does not match expected (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected, keyStr)
		}
	}
}

// Tests that changing single and multiple inputs to newMessageKey always
// results in a unique key.
func Test_newMessageKey_Unique(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	const n = 10
	nonces := make([]format.Fingerprint, n)
	symKeys := make([][]byte, n)

	for i := range nonces {
		nonces[i] = format.Fingerprint{}
		prng.Read(nonces[i][:])
		symKeys[i] = make([]byte, 16)
		prng.Read(symKeys[i])
	}

	keys := make(map[string]bool, n*n)

	for i, nonce := range nonces {
		for j, symKey := range symKeys {
			key := newMessageKey(nonce, symKey)
			keyStr := base64.StdEncoding.EncodeToString(key)

			if keys[keyStr] {
				t.Errorf("Message key already exists in map (%d, %d)."+
					"\nkey: %v\nnonce: %s\nsymKey: %v",
					i, j, key, nonce, symKey)
			} else {
				keys[keyStr] = true
			}
		}
	}
}
