package singleUse

import (
	"encoding/binary"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/hash"
)

const requestPartKeySalt = "singleUseRequestKeySalt"

// NewRequestPartKey generates the key for the request message that corresponds
// with the given key number.
func NewRequestPartKey(dhKey *cyclic.Int, keyNum uint64) []byte {
	// Create new hash
	h, err := hash.NewCMixHash()
	if err != nil {
		jww.ERROR.Panicf(
			"[SU] Failed to create new hash for single-use request key: %v", err)
	}

	keyNumBytes := make([]byte, binary.MaxVarintLen64)
	binary.BigEndian.PutUint64(keyNumBytes, keyNum)

	// Hash the DH key, key number, and salt
	h.Write(dhKey.Bytes())
	h.Write(keyNumBytes)
	h.Write([]byte(requestPartKeySalt))

	// Get hash bytes
	return h.Sum(nil)
}
