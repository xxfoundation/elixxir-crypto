////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Packagee 2e contains functions used in the end-to-end encryption algorithm, including
// the end-to-end key rotation.
package e2e

import (
	"crypto/sha256"
	"encoding/binary"
	"gitlab.com/elixxir/crypto/cyclic"
	hash2 "gitlab.com/elixxir/crypto/hash"
	"gitlab.com/xx_network/primitives/id"
	"hash"
)

const EMERGENCY_KEY_STR = "EMERGENCY"

// deriveSingleKey derives a single key by calling ExpandKey using the passed hash
// The basekey data is the blake2b hash of passed data and id
func deriveSingleKey(h hash.Hash, g *cyclic.Group, data []byte, id uint) *cyclic.Int {
	idBytes := make([]byte, binary.MaxVarintLen32)
	n := binary.PutUvarint(idBytes, uint64(id))
	b, _ := hash2.NewCMixHash()
	b.Write(data)
	b.Write(idBytes[:n])
	return hash2.ExpandKey(h, g, b.Sum(nil), g.NewInt(1))
}

// deriveKeysCore derives multiple keys using the specified hash function
// It creates the data bytes by concatenating dhkey, userID and
// additionally emergency string for emergency keys
// Then loops calls to deriveSingleKey to generate nkeys
func deriveKeysCore(h hash.Hash, g *cyclic.Group, dhkey *cyclic.Int,
	userID *id.ID, emergency bool, nkeys uint) []*cyclic.Int {
	data := append(dhkey.Bytes(), userID.Bytes()...)
	if emergency {
		data = append(data, []byte(EMERGENCY_KEY_STR)...)
	}
	keys := make([]*cyclic.Int, nkeys)
	var i uint
	for i = 0; i < nkeys; i++ {
		keys[i] = deriveSingleKey(h, g, data, i)
	}
	return keys
}

// DeriveKeys derives nkeys keys using blake2b as the hash function for key expansion
// UserID should be your own for generating encryption keys
// or the receiving userID for generating decryption keys
func DeriveKeys(g *cyclic.Group, dhkey *cyclic.Int, userID *id.ID,
	nkeys uint) []*cyclic.Int {
	h, _ := hash2.NewCMixHash()
	return deriveKeysCore(h, g, dhkey, userID, false, nkeys)
}

// DeriveEmergencyKeys derives nkeys keys using sha256 as the hash function for key expansion
// UserID should be your own for generating encryption keys
// or the receiving userID for generating decryption keys
// Use this to generate emergency keys
func DeriveEmergencyKeys(g *cyclic.Group, dhkey *cyclic.Int, userID *id.ID, nkeys uint) []*cyclic.Int {
	return deriveKeysCore(sha256.New(), g, dhkey, userID, true, nkeys)
}
