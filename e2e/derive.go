package e2e

import (
	"encoding/binary"
	"hash"
)

// derive creates a bit key from a key id and a byte slice by hashing them
// with the passed hash function. it will have the size of the output of the
// hash function
func derive(h hash.Hash, data []byte, id uint32) []byte {
	//convert the
	keyIdBytes := make([]byte, binary.MaxVarintLen32)
	n := binary.PutUvarint(keyIdBytes, uint64(id))
	h.Write(data)
	h.Write(keyIdBytes[:n])
	return h.Sum(nil)
}
