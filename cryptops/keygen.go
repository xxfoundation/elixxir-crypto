package cryptops

import (
	"gitlab.com/privategrity/crypto/cyclic"
	"gitlab.com/privategrity/crypto/hash"
)

// Generates a new shared key
// out is an optional parameter that allows you to pre-allocate a big integer
// TODO: ensure that we put out the correct key length (close to prime length)
// to make the distribution as uniform as possible
func GenerateSharedKey(byteLength int, g *cyclic.Group, baseKey,
	prevRecursiveKey, outRecursiveKey, outSharedKey *cyclic.Int) *cyclic.Int {
	// TODO: don't construct new hash every time
	hash, _ := hash.NewCMixHash()

	sharedKey := baseKey.Bytes()

	// F(x)
	hash.Write(sharedKey)
	// hash.Sum behaves similarly to append() for slices
	sharedKey = hash.Sum(nil)

	// G(x)
	hash.Write(prevRecursiveKey.Bytes())
	sharedKey = hash.Sum(sharedKey)
	for len(sharedKey) < byteLength {
		// each iteration of G adds 32 to the length of the shared key
		hash.Write(sharedKey)
		sharedKey = hash.Sum(sharedKey)
	}

	// limit the length of the recursive key output
	one := cyclic.NewInt(1)
	g.Mul(one, cyclic.NewIntFromBytes(sharedKey), outRecursiveKey)

	// H(x)
	hash.Write(sharedKey)
	sharedKey = hash.Sum(sharedKey)

	// limit the length of the shared key output
	g.Mul(one, cyclic.NewIntFromBytes(sharedKey), outSharedKey)

	return outSharedKey
}
