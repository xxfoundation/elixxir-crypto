package cryptops

import (
	"gitlab.com/privategrity/crypto/cyclic"
	"gitlab.com/privategrity/crypto/hash"
)

func GenerateKey(toHash *cyclic.Int, byteLength int) *cyclic.Int {
	// TODO: don't construct new hash every time
	h, err := hash.NewCMixHash()

	if err != nil {
		println("Failed to construct the hash function. This should",
			"never happen.")
		println(err.Error)
	}

	var result []byte

	// F(x)
	h.Write(toHash.Bytes())
	result = h.Sum(result)

	// G(x)
	for len(result) < byteLength {
		h.Write(result)
		result = h.Sum(result)
		println(h.Size())
	}

	// H(x)
	h.Write(result)
	result = h.Sum(result)

	return cyclic.NewIntFromBytes(result[:byteLength])
}
