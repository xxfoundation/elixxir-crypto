////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

// Package hash includes a general-purpose hashing algorithm, blake2b,
// that should be suitable for most of our needs.
// It also includes functions to calculate an HMAC.
package hash

import (
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/crypto/csprng"
	"gitlab.com/elixxir/crypto/cyclic"
	"gitlab.com/elixxir/crypto/large"
	"golang.org/x/crypto/hkdf"
	"hash"
)

// ExpandKey is a function that receives a key and expands such key to the size
// of the prime group
func ExpandKey(h hash.Hash, g *cyclic.Group, key []byte,
	output *cyclic.Int) *cyclic.Int {
	// The Hash will be created outside the function, so need to wrap
	// it into a function to pass to HKDF.Expand
	var foo = func() hash.Hash {
		return h
	}
	keyGen := hkdf.Expand(foo, key, nil)

	pBytes := g.GetPBytes()
	expandedKey, err := csprng.GenerateInGroup(pBytes, len(pBytes), keyGen)
	if err != nil {
		jww.FATAL.Panicf("Key expansion failure: %v", err)
	}

	keyInt := large.NewInt(0)
	keyInt.SetBytes(expandedKey)
	g.SetLargeInt(output, keyInt)

	return output
}
