package hash

import (
	"hash"
	"golang.org/x/crypto/blake2b"
)

// NewCMixHash returns the current cMix hash implementation
// which is currently the 256 bit version of blake2b
func NewCMixHash() (hash.Hash, error) {
	return blake2b.New256(nil)
}
