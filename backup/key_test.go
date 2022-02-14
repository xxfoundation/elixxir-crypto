package backup

import (
	"bytes"
	"encoding/base64"
	"gitlab.com/xx_network/crypto/csprng"
	"testing"
)

// Tests that DeriveKey returns a key of the correct length and that it is the
// same for the same set of password and salt. Also checks that keys with the
// same salt or passwords do not collide.
func TestDeriveKey(t *testing.T) {
	p := testParams()
	salts := make([][]byte, 6)
	passwords := make([]string, len(salts))
	keys := make(map[string]bool, len(salts)*len(passwords))

	for i := range salts {
		prng := csprng.NewSystemRNG()
		salt, _ := MakeSalt(prng)
		salts[i] = salt

		password := make([]byte, 16)
		_, _ = prng.Read(password)
		passwords[i] = base64.StdEncoding.EncodeToString(password)[:16]
	}

	for _, salt := range salts {
		for _, password := range passwords {
			key := DeriveKey(password, salt, p)

			// Check that the length of the key is correct
			if len(key) != KeyLen {
				t.Errorf("Incorrect key length.\nexpected: %d\nreceived: %d",
					KeyLen, len(key))
			}

			// Check that the same key is generated when the same password and salt
			// are used
			key2 := DeriveKey(password, salt, p)

			if !bytes.Equal(key, key2) {
				t.Errorf("Keys with same password and salt do not match."+
					"\nexpected: %v\nreceived: %v", key, key2)
			}

			if keys[string(key)] {
				t.Errorf("Key already exists.")
			}
			keys[string(key)] = true
		}
	}
}

// Tests that multiple calls to MakeSalt results in unique salts of the
// specified length.
func TestMakeSalt(t *testing.T) {
	salts := make(map[string]bool, 50)
	for i := 0; i < 50; i++ {
		salt, err := MakeSalt(csprng.NewSystemRNG())
		if err != nil {
			t.Errorf("MakeSalt returned an error: %+v", err)
		}

		if len(salt) != SaltLen {
			t.Errorf("Incorrect salt length.\nexpected: %d\nreceived: %d",
				SaltLen, len(salt))
		}

		if salts[string(salt)] {
			t.Errorf("Salt already exists (%d).", i)
		}
		salts[string(salt)] = true
	}
}
