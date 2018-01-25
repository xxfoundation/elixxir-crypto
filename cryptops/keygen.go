package cryptops

import (
	"gitlab.com/privategrity/crypto/cyclic"
	"gitlab.com/privategrity/crypto/hash"
)

// Combine two keys without losing entropy
func bitwiseXOR(a []byte, b []byte, out []byte) []byte {
	for i := 0; i < len(a); i++ {
		out[i] = a[i] ^ b[i]
	}

	return out
}

// Generates a new shared key
// Calling this method will mutate recursiveKey, outSharedKey, and
// outSharedKeyStorage
func GenerateSharedKey(g *cyclic.Group, baseKey, recursiveKey,
	outSharedKey *cyclic.Int, outSharedKeyStorage []byte) *cyclic.Int {
	if baseKey.BitLen() != 256 {
		panic("Base key has non-256 bit length")
	}
	if recursiveKey.BitLen() != 256 {
		panic("Recursive key has non-256 bit length")
	}

	hash, _ := hash.NewCMixHash()
	// Used to increment the recursive key while constructing the long key
	temp := cyclic.NewInt(1)

	// F(x)
	hash.Reset()
	hash.Write(baseKey.Bytes())
	fOut := hash.Sum(nil)

	// G(x)
	hash.Reset()
	// combine fOut and recursiveKey without losing entropy
	fOut = bitwiseXOR(fOut, recursiveKey.Bytes(), fOut)
	hash.Write(fOut)
	recursiveKey.SetBytes(hash.Sum(nil))

	// H(x)
	hash.Reset()
	hashInput := cyclic.NewIntFromBytes(recursiveKey.Bytes())

	outSharedKeyStorage = outSharedKeyStorage[:0]
	// each iteration of H adds 256 bits to the length of the shared key
	for len(outSharedKeyStorage) < cap(outSharedKeyStorage) {
		// increment hash input
		hashInput = hashInput.Add(temp, hashInput)
		hash.Reset()
		hash.Write(hashInput.Bytes())
		outSharedKeyStorage = hash.Sum(outSharedKeyStorage)
	}

	// limit the length of the shared key output with a modulus
	outSharedKey.SetBytes(outSharedKeyStorage)
	g.ModP(outSharedKey, outSharedKey)

	return outSharedKey
}
