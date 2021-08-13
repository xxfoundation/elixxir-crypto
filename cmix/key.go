////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Package cmix derives new keys within the cyclic group from salts and a
// symmetric key, locked to a monotonic roundID counter. It also is used for
// managing keys and salts for communication between clients
package cmix

import (
	"crypto/sha256"
	"encoding/binary"
	"git.xx.network/elixxir/crypto/cyclic"
	"git.xx.network/elixxir/crypto/hash"
	"git.xx.network/xx_network/primitives/id"
	goHash "hash"
)

const keyGenerationSalt = "cmixClientNodeKeyGenerationSalt"

// ClientKeyGen generate encryption key for clients.
func ClientKeyGen(grp *cyclic.Group, salt []byte, roundID id.Round,
	symmetricKeys []*cyclic.Int) *cyclic.Int {
	output := grp.NewInt(1)
	tmpKey := grp.NewInt(1)

	// Multiply all the generated keys together as they are generated.
	for _, symmetricKey := range symmetricKeys {
		keyGen(grp, salt, roundID, symmetricKey, tmpKey)
		grp.Mul(tmpKey, output, output)
	}

	grp.Inverse(output, output)

	return output
}

// NodeKeyGen generates encryption key for nodes.
func NodeKeyGen(grp *cyclic.Group, salt []byte, roundID id.Round, symmetricKey, output *cyclic.Int) {
	keyGen(grp, salt, roundID, symmetricKey, output)
}

// keyGen combines the salt with the baseKey to generate a new key inside the group.
func keyGen(grp *cyclic.Group, salt []byte, roundID id.Round, symmetricKey, output *cyclic.Int) *cyclic.Int {
	h1, _ := hash.NewCMixHash()
	h2 := sha256.New()

	// get the bytes of the symmetric key
	a := symmetricKey.Bytes()

	// get the bytes of the roundID (monotonic counter)
	m := make([]byte, 8)
	binary.BigEndian.PutUint64(m, uint64(roundID))

	// Blake2b Hash of the result of previous stage (base key + salt)
	h1.Write(a)
	h1.Write(salt)
	h1.Write(m)
	h1.Write([]byte(keyGenerationSalt))
	x := h1.Sum(nil)

	// Different Hash (SHA256) of the previous result to add entropy
	h2.Write(x)
	y := h2.Sum(nil)

	// Expand Key using SHA512
	hashFunc := func() goHash.Hash { return sha256.New() }
	k := hash.ExpandKey(hashFunc, grp, y, output)
	return k
}
