package broadcast

import (
	"encoding/base64"
	"gitlab.com/xx_network/crypto/signature/rsa"
	"gitlab.com/xx_network/primitives/id"
	"io"
	"math/rand"
	"testing"
)

// Tests consistency of newReceptionID.
func Test_newReceptionID_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	expectedIDs := []string{
		"jY7hXZwPkuC3IVN+0dobGGLCbHdzU6LUU081KGdHFY8D",
		"E8vfDIqrwGnZsWJ8nmHjATQRh0lx8ajyd1Z4I5cGHRID",
		"B6Iasws7vYGK9YPn6w8rMxZ7uNtPLpnbG25umJ7dQ7QD",
		"1O+l1iMg1vVykmmPy7lNRzt/FPq9vhqscJo9+d5v8/MD",
		"f30wli7uTpOX3N+qkJQ/WazHCFoxveyqK0FHe4ePbb4D",
		"hxMaHPjGc+0P2YsXtFoXUGPyEAYup7816uMzhLCrzwUD",
		"JSYk+aZaGmpklb6pw10ktpXlXUq6N9hdjSO0b8EY3bcD",
		"ALV/r0cYnsKhH09t8+NsKortwfWCW7Ei6ZareaT1kkID",
		"Se5h+o4HgO5XYln7EJNhfHP1QIwK8j14DO4S2Do0dEYD",
		"CY9/ty4aqKRF2S9bTqE+Gy3WcYhNGdpMmRIwLxlrZQcD",
	}

	rsaPubKeys := []string{
		"MBACCQDA5DQWgAUyOQIDAQAB", "MBACCQCpfsFIJbH7oQIDAQAB",
		"MBACCQDHO1TuIaG2AwIDAQAB", "MBACCQCiBM9dhnOHkwIDAQAB",
		"MBACCQCssQfBWeYW2wIDAQAB", "MBACCQC3uzm5dC4BPQIDAQAB",
		"MBACCQDOMmDxCKj7cQIDAQAB", "MBACCQDCMvk9bfadaQIDAQAB",
		"MBACCQDj1obCHCwwRQIDAQAB", "MBACCQC1hNgOtRw7twIDAQAB",
	}

	for i, expected := range expectedIDs {
		symKey := make([]byte, 16)
		prng.Read(symKey)
		symSalt := make([]byte, 32)
		prng.Read(symSalt)
		name := randomString(12, prng, t)
		description := randomString(36, prng, t)

		rsaPubKey, err := rsa.LoadPublicKeyFromPem([]byte(
			"-----BEGIN RSA PUBLIC KEY-----\n" + rsaPubKeys[i] +
				"\n-----END RSA PUBLIC KEY-----"))
		if err != nil {
			t.Errorf("Failed to load public RSA from pem: %+v", err)
		}

		receptionID := newReceptionID(name, description, symSalt, rsaPubKey)

		if expected != receptionID.String() {
			t.Errorf("Reception ID does not match expected (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected, receptionID)
		}
	}
}

// Tests that changing single and multiple inputs to newReceptionID always
// results in a unique reception ID.
func Test_newReceptionID_Unique(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	const n = 2
	symKeys, symSalts := make([][]byte, n), make([][]byte, n)
	names, descriptions := make([]string, n), make([]string, n)
	rsaPubKeys := make([]*rsa.PublicKey, n)

	for i := range rsaPubKeys {
		symKeys[i] = make([]byte, 16)
		prng.Read(symKeys[i])
		symSalts[i] = make([]byte, 32)
		prng.Read(symSalts[i])
		names[i] = randomString(12, prng, t)
		descriptions[i] = randomString(32, prng, t)
		rsaPubKeys[i] = newRsaPubKey(prng, t)
	}

	receptionIDs := make(map[id.ID]bool, n*n*n*n*n)

	for i, name := range names {
		for j, description := range descriptions {
			for k, symSalt := range symSalts {
				for l, rsaPubKey := range rsaPubKeys {
					receptionID := newReceptionID(name, description, symSalt, rsaPubKey)

					if receptionIDs[*receptionID] {
						t.Errorf("Reception ID already exists in map "+
							"(%d, %d, %d, %d).\nreceptionID: %s",
							i, j, k, l, receptionID)
					} else {
						receptionIDs[*receptionID] = true
					}
				}
			}
		}
	}
}

// Tests consistency of newReceptionIdSalt.
func Test_newReceptionIdSalt_Consistency(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	expectedSalts := []string{
		"Z+Tee5XVnjy2Ecn5PK+UwWyX/dEbB0EPbf4JIwuMHHo=",
		"sTA1/SrnvyG7RJnKJm5Cj5ZyB86hnYbeajJfc0OVMKI=",
		"aErhgXTirlSLNwmArhBKoyGG53lAQSA/NXk67+q4DBo=",
		"ptVYHwPeafiapjLqORti3THmdVvA7zMLGr5Xy9alVgM=",
		"84Lhm/KspJPyjF0qiUs9U09AU6aKI8vtem0pvHxhYTg=",
		"O+b1L7PEJ/sYAnqMymhlfCmbNMMYj+W6FcCYHQP0Izc=",
		"KYtvhyMXcUXS8WWFfDGTRxi+9E+HJL341TJwMxNVT7c=",
		"lY7tvSm6gonSu1Rq3ZugmOYv7sfuk7yr96IYQWxkOec=",
		"BZJDptsDe1bl0WHnSLnuRZ9R2i+e6hVp/T+JTWu6LJU=",
		"gLuHJ5g+RrWSTpEFXYH28qfb2RgQb4TplFNQDF7edZo=",
	}

	for i, expected := range expectedSalts {
		symKey := make([]byte, 16)
		prng.Read(symKey)
		symSalt := make([]byte, 32)
		prng.Read(symSalt)
		name := randomString(12, prng, t)
		description := randomString(36, prng, t)

		salt := newReceptionIdSalt(symSalt, name, description)
		saltStr := base64.StdEncoding.EncodeToString(salt)

		if expected != saltStr {
			t.Errorf("Salt does not match expected (%d)."+
				"\nexpected: %s\nreceived: %s", i, expected, saltStr)
		}
	}
}

// Tests that changing single and multiple inputs to newReceptionIdSalt always
// results in a unique salt.
func Test_newReceptionIdSalt_Unique(t *testing.T) {
	prng := rand.New(rand.NewSource(42))
	const n = 5
	symKeys, symSalts := make([][]byte, n), make([][]byte, n)
	names, descriptions := make([]string, n), make([]string, n)

	for i := range symKeys {
		symKeys[i] = make([]byte, 16)
		prng.Read(symKeys[i])
		symSalts[i] = make([]byte, 32)
		prng.Read(symSalts[i])
		names[i] = randomString(12, prng, t)
		descriptions[i] = randomString(32, prng, t)
	}

	salts := make(map[string]bool, n*n*n*n)

	for i, symSalt := range symSalts {
		for j, name := range names {
			for k, description := range descriptions {
				salt := newReceptionIdSalt(symSalt, name, description)
				saltStr := base64.StdEncoding.EncodeToString(salt)

				if salts[saltStr] {
					t.Errorf("Salt already exists in map (%d, %d, %d)."+
						"\nsalt: %s\nname: %q\ndescrption: %q",
						i, j, k, saltStr, name, description)
				} else {
					salts[saltStr] = true
				}
			}
		}
	}
}

// randomString generates a random base 64 encoded string of the given length.
func randomString(n int, rng io.Reader, t *testing.T) string {
	b := make([]byte, n)
	read, err := rng.Read(b)
	if err != nil {
		t.Errorf("Failed to read random bytes: %+v", err)
	} else if read != n {
		t.Errorf("Read %d bytes, expected %d bytes", read, n)
	}

	return base64.StdEncoding.EncodeToString(b)[:n]
}

// newRsaPubKey generates a new random RSA public key.
func newRsaPubKey(rng io.Reader, t *testing.T) *rsa.PublicKey {
	pk, err := rsa.GenerateKey(rng, 64)
	if err != nil {
		t.Errorf("Failed to generate new RSA key: %+v", err)
	}
	return pk.GetPublic()
}
