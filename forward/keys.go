////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package forward

import (
	"crypto/sha512"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/cyclic"
	"golang.org/x/crypto/hkdf"
	"hash"
)

// ExpandKey is a function that receives a key and expands such key to a specific size
// This implementation returns a 2048 bit-size key (or 256 bytes)
func ExpandKey(g *cyclic.Group, key []byte) []byte {
	keyGen := hkdf.Expand(sha512.New, key, nil)
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

// UpdateKey is a function that updates the current Key to be used to encrypt/decrypt
// This function receives a base key generated during the registration and adds entropy by using
// two different hash functions and then expands the output from the hash functions to generate a bigger key
func UpdateKey(g *cyclic.Group, baseKey, salt []byte, b hash.Hash, h hash.Hash) []byte {

	// Append the base key and the received salt to generate a random input
	a := append(baseKey, salt...)

	//Blake2b Hash of the result of previous stage (base key + salt)
	b.Reset()
	b.Write(a)
	x := b.Sum(nil)

	//Different Hash (SHA256) of the previous result to add entropy
	h.Reset()
	h.Write(x)
	y := h.Sum(nil)

	// Expand Key
	z := ExpandKey(g, y)

	return z
}
