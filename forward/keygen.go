package forward

import (
	"gitlab.com/privategrity/crypto/cyclic"
	"gitlab.com/privategrity/crypto/hash"
	jww "github.com/spf13/jwalterweatherman"
)

const hashLen uint64 = 32

var runRatchet bool = true

func SetRatchetStatus(status bool){
	runRatchet = status
	if !status{
		jww.WARN.Println("Ratcheting has been disabled")
	}
}

func GetRatchetStatus()(bool){
	return runRatchet
}


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

	if !runRatchet{
		jww.WARN.Println("Base Key * Recursive Key returned; " +
			"ratcheting is disabled")
		g.Mul(baseKey,recursiveKey,outSharedKey)

		return outSharedKey
	}

	if baseKey.BitLen() > 256 {
		panic("Base key is too long")
	}
	if recursiveKey.BitLen() > 256 {
		panic("Recursive key is too long")
	}

	fwhash, _ := hash.NewCMixHash()
	// Used to increment the recursive key while constructing the long key
	temp := cyclic.NewInt(1)

	// F(x)
	fwhash.Reset()
	fwhash.Write(baseKey.LeftpadBytes(hashLen))
	fOut := fwhash.Sum(nil)

	// G(x)
	fwhash.Reset()
	// combine fOut and recursiveKey without losing entropy
	bitwiseXOR(fOut, recursiveKey.LeftpadBytes(hashLen), fOut)
	fwhash.Write(fOut)
	recursiveKey.SetBytes(fwhash.Sum(nil))

	// H(x)
	fwhash.Reset()
	hashInput := cyclic.NewIntFromBytes(recursiveKey.LeftpadBytes(hashLen))

	outSharedKeyStorage = outSharedKeyStorage[:0]
	// each iteration of H adds 256 bits to the length of the shared key
	for len(outSharedKeyStorage) < cap(outSharedKeyStorage) {
		// increment hash input
		hashInput = hashInput.Add(temp, hashInput)
		fwhash.Reset()
		fwhash.Write(hashInput.Bytes())
		outSharedKeyStorage = fwhash.Sum(outSharedKeyStorage)
	}

	// limit the length of the shared key output with a modulus
	outSharedKey.SetBytes(outSharedKeyStorage)
	g.ModP(outSharedKey, outSharedKey)

	return outSharedKey
}
