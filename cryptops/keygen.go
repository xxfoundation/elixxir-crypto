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

// Limit key bit length to a multiple of the prime's bit length
func limitKeyLength(sharedKey []byte, prime *cyclic.Int) []byte {
	sharedKeyLength := cyclic.NewIntFromBytes(sharedKey).BitLen()
	println(sharedKeyLength)
	bitsToZero := sharedKeyLength % prime.BitLen()
	println("Bits to zero:")
	println(bitsToZero)
	bitsZeroed := 0

	// zero most of the bits that we need to zero
	i := 0
	for i < bitsToZero/8 {
		sharedKey[i] = 0
		// debug
		sharedKeyLength = cyclic.NewIntFromBytes(sharedKey).BitLen()
		println("Shared key statistics:")
		println(sharedKeyLength)
		println(sharedKeyLength % prime.BitLen())
		println(sharedKeyLength / prime.BitLen())
		// end debug
		i++
		bitsZeroed += 8
	}

	// zero the last few bits
	bitMask := byte(1 << 7)
	for bitsZeroed < bitsToZero {
		bitsZeroed++
		sharedKey[i] = sharedKey[i] &^ bitMask
		// debug
		sharedKeyLength = cyclic.NewIntFromBytes(sharedKey).BitLen()
		println("Shared key statistics:")
		println(sharedKeyLength)
		println(sharedKeyLength % prime.BitLen())
		println(sharedKeyLength / prime.BitLen())
		// end debug
		bitMask >>= 1
	}

	return sharedKey
}

// Generates a new shared key
// Calling this method will mutate recursiveKey
// TODO: is it better to take bitLength instead of byteLength?
// it might make the function more complicated
func GenerateSharedKey(byteLength int, g *cyclic.Group, baseKey,
	recursiveKey, outSharedKey *cyclic.Int) *cyclic.Int {
	if baseKey.BitLen() != 256 {
		panic("Base key has non-256 bit length")
	}
	if recursiveKey.BitLen() != 256 {
		panic("Recursive key has non-256 bit length")
	}

	// TODO: don't construct new hash every time
	hash, _ := hash.NewCMixHash()
	temp := cyclic.NewInt(1)

	// F(x)
	hash.Reset()
	hash.Write(baseKey.Bytes())
	fOut := hash.Sum(nil)

	// G(x)
	hash.Reset()
	fOut = bitwiseXOR(fOut, recursiveKey.Bytes(), fOut)
	hash.Write(fOut)
	recursiveKey.SetBytes(hash.Sum(nil))

	// H(x)
	hash.Reset()
	sharedKey := make([]byte, 0, byteLength)
	hashInput := cyclic.NewIntFromBytes(recursiveKey.Bytes())

	// each iteration of H adds 256 bits to the length of the shared key
	for len(sharedKey) < byteLength {
		// increment hash input
		hashInput = hashInput.Add(temp, hashInput)
		hash.Reset()
		hash.Write(hashInput.Bytes())
		sharedKey = hash.Sum(sharedKey)
	}

	// limit the length of the shared key output with a modulus
	g.GetP(temp)
	sharedKey = limitKeyLength(sharedKey, temp)
	outSharedKey.SetBytes(sharedKey)
	outSharedKey.Mod(temp, outSharedKey)

	return outSharedKey
}
