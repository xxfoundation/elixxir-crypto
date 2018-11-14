////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package forward

import (
	"crypto/sha512"
	"golang.org/x/crypto/pbkdf2"
	"hash"
)

// ExpandKey is a function that receives a key and a salt and expands such key to a specific size
// This implementation returns a 2048 bit-size key (or 256 bytes)
func ExpandKey(key []byte, salt []byte) []byte {

	return pbkdf2.Key(key, salt, 1, 256, sha512.New)
}

// UpdateKey is a function that updates the current Key to be used to encrypt/decrypt
// This function receives a base key generated during the registration and adds entropy by using
// two different hash functions and then expands the output from the hash functions to generate a bigger key
func UpdateKey(baseKey, salt []byte, b hash.Hash, h hash.Hash) []byte {

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
	z := ExpandKey(y, salt)

	return z
}
