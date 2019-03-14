package e2e

import (
	"crypto/sha256"
	"encoding/binary"
	"gitlab.com/elixxir/crypto/cyclic"
	hash2 "gitlab.com/elixxir/crypto/hash"
	"gitlab.com/elixxir/primitives/id"
	"hash"
)

// This function derives a single key by calling ExpandKey using the passed hash
// The basekey data is the blake2b hash of passed data and id
func deriveSingleKey(h hash.Hash, g *cyclic.Group, data []byte, id uint) []byte {
	idBytes := make([]byte, binary.MaxVarintLen32)
	n := binary.PutUvarint(idBytes, uint64(id))
	b, _ := hash2.NewCMixHash()
	b.Write(data)
	b.Write(idBytes[:n])
	return hash2.ExpandKey(h, g, b.Sum(nil))
}

// This function derives multiple keys using the specified hash function
// It creates the data bytes by concatenating dhkeyID, user and partnerID
// and then loops calls to deriveSingleKey
func deriveKeysCore(h hash.Hash, g *cyclic.Group, dhkey *cyclic.Int,
	userID, partnerID *id.User, num uint) []*cyclic.Int {
	data := append([]byte{}, dhkey.Bytes()...)
	data = append(data, userID.Bytes()...)
	data = append(data, partnerID.Bytes()...)
	keys := make([]*cyclic.Int, num)
	var i uint
	for i = 0; i < num; i++ {
		keys[i] = cyclic.NewIntFromBytes(deriveSingleKey(h, g, data, i))
	}
	return keys
}

// This function derives num keys using blake2b as the hash function
// for key expansion
func DeriveKeys(g *cyclic.Group, dhkey *cyclic.Int,
	userID, partnerID *id.User, num uint) []*cyclic.Int {
	h, _ := hash2.NewCMixHash()
	return deriveKeysCore(h, g, dhkey, userID, partnerID, num)
}

// This function derives num keys using sha256 as the hash function
// for key expansion
func DeriveReKeys(g *cyclic.Group, dhkey *cyclic.Int,
	userID, partnerID *id.User, num uint) []*cyclic.Int {
	return deriveKeysCore(sha256.New(), g, dhkey, userID, partnerID, num)
}
