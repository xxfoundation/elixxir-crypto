package cmix

import (
	"bytes"
	"gitlab.com/elixxir/crypto/cyclic"
	"hash"
)

// GenerateKMAC hashes the salt and base key together using the passed in hashing
// algorithm to produce a kmac
func GenerateKMAC(salt []byte, baseKey *cyclic.Int, h hash.Hash) []byte {
	h.Reset()
	h.Write(baseKey.Bytes())
	h.Write(salt)
	return h.Sum(nil)
}

// GenerateKMACs creates a list of KMACs all with the same salt but different
// base keys
func GenerateKMACs(salt []byte, baseKeys []*cyclic.Int, h hash.Hash) [][]byte {
	kmacs := make([][]byte, len(baseKeys))

	for i, baseKey := range baseKeys {
		kmacs[i] = GenerateKMAC(salt, baseKey, h)
	}

	return kmacs
}

// VerifyKMAC verifies that the generated GenerateKMAC is the same as the passed in GenerateKMAC
func VerifyKMAC(expectedKmac, salt []byte, baseKey *cyclic.Int, h hash.Hash) bool {
	generated := GenerateKMAC(salt, baseKey, h)

	if len(generated) != len(expectedKmac) {
		return false
	}

	return bytes.Compare(expectedKmac, generated) == 0
}
