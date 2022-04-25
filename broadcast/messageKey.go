package broadcast

import (
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/primitives/format"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"
	"hash"
)

// Error messages.
const (
	// newMessageKey
	errNewMessageKeyHash = "[BCAST] Failed to create new hash for key for " +
		"broadcast cMix message: %+v"
)

// newMessageKey generates a new key for a broadcast cMix message using HKDF.
func newMessageKey(nonce format.Fingerprint, symKey []byte) []byte {
	// Underlying hash function
	h := func() hash.Hash {
		h, _ := blake2b.New256(nil)
		return h
	}

	key := make([]byte, 32)
	n, err := hkdf.New(h, symKey, nonce[:], nil).Read(key[:])
	if err != nil || n != len(key) {
		jww.FATAL.Panicf(errNewMessageKeyHash, err)
	}

	return key
}
