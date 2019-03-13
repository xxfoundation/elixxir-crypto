////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package hash

import (
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/cyclic"
	"golang.org/x/crypto/hkdf"
	"hash"
)

// ExpandKey is a function that receives a key and expands such key to a specific size
// This implementation returns a 2048 bit-size key (or 256 bytes)
func ExpandKey(h hash.Hash, g *cyclic.Group, key []byte) []byte {
	// The Hash will be created outside the function, so need to wrap
	// it into a function to pass to HKDF.Expand
	var foo = func() hash.Hash {
		return h
	}
	keyGen := hkdf.Expand(foo, key, nil)
	keyInt := cyclic.NewInt(0)
	expandedKey := make([]byte, g.GetP(nil).BitLen()>>3)
	// Make sure generated key is in the group
	for !g.Inside(keyInt) {
		size, err := keyGen.Read(expandedKey)
		if err != nil || size != len(expandedKey) {
			jww.FATAL.Panicf("Could not expand key: %v", err.Error())
		}
		keyInt.SetBytes(expandedKey)
	}
	return expandedKey
}
