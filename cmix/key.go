////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package cmix

import (
	"crypto/sha256"
	"crypto/sha512"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/hash"
)

// ClientKeyGen generate encryption key for clients.
func ClientKeyGen(grp *cyclic.Group, salt []byte, baseKeys []*cyclic.Int) *cyclic.Int {
	output := grp.NewInt(1)
	tmpKey := grp.NewInt(1)

	// Multiply all the generated keys together as they are generated.
	for _, baseKey := range baseKeys {
		keyGen(grp, salt, baseKey, tmpKey)
		grp.Mul(tmpKey, output, output)
	}

	grp.Inverse(output, output)

	return output
}

// NodeKeyGen generates encryption key for nodes.
func NodeKeyGen(grp *cyclic.Group, salt []byte, baseKey, output *cyclic.Int) {
	keyGen(grp, salt, baseKey, output)
}

// keyGen combines the salt with the baseKey to generate a new key inside the group.
func keyGen(grp *cyclic.Group, salt []byte, baseKey, output *cyclic.Int) *cyclic.Int {
	h1, _ := hash.NewCMixHash()
	h2 := sha256.New()

	a := baseKey.Bytes()

	// Blake2b Hash of the result of previous stage (base key + salt)
	h1.Reset()
	h1.Write(a)
	h1.Write(salt)
	x := h1.Sum(nil)

	// Different Hash (SHA256) of the previous result to add entropy
	h2.Reset()
	h2.Write(x)
	y := h2.Sum(nil)

	// Expand Key using SHA512
	return hash.ExpandKey(sha512.New(), grp, y, output)
}
