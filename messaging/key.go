////////////////////////////////////////////////////////////////////////////////
// Copyright © 2018 Privategrity Corporation                                   /
//                                                                             /
// All rights reserved.                                                        /
////////////////////////////////////////////////////////////////////////////////

package messaging

import (
	"crypto/sha256"
	"crypto/sha512"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/hash"
)

// NewEncryptionKey combines the salt with the baseKey to generate
// a new key inside the group.
func NewEncryptionKey(salt []byte, baseKey *cyclic.Int, group *cyclic.Group) *cyclic.Int {
	k := NewDecryptionKey(salt, baseKey, group)
	group.Inverse(k, k)
	return k
}

// NewEncryptionKeys calls NewEncryptionKey for each of the baseKeys
func NewEncryptionKeys(salt []byte, baseKeys []*cyclic.Int,
	group *cyclic.Group) []*cyclic.Int {
	keys := make([]*cyclic.Int, len(baseKeys))
	for i := range baseKeys {
		keys[i] = NewEncryptionKey(salt, baseKeys[i], group)
	}
	return keys
}

// NewDecryptionKey combines the salt with the baseKey to generate
// a new key inside the group.
func NewDecryptionKey(salt []byte, baseKey *cyclic.Int, group *cyclic.Group) *cyclic.Int {
	h1, _ := hash.NewCMixHash()
	h2 := sha256.New()

	a := baseKey.Bytes()

	//Blake2b Hash of the result of previous stage (base key + salt)
	h1.Reset()
	h1.Write(a)
	h1.Write(salt)
	x := h1.Sum(nil)

	//Different Hash (SHA256) of the previous result to add entropy
	h2.Reset()
	h2.Write(x)
	y := h2.Sum(nil)

	// Expand Key
	// Use SHA512
	z := hash.ExpandKey(sha512.New(), group, y)

	r := cyclic.NewIntFromBytes(z)

	return r
}

// NewDecryptionKeys calls NewDecryptionKey for each of the baseKeys
func NewDecryptionKeys(salt []byte, baseKeys []*cyclic.Int,
	group *cyclic.Group) []*cyclic.Int {
	keys := make([]*cyclic.Int, len(baseKeys))
	for i := range baseKeys {
		keys[i] = NewDecryptionKey(salt, baseKeys[i], group)
	}
	return keys
}
